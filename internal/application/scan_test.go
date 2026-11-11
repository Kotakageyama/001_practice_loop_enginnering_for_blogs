package application

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"pentest/internal/domain/portscan"
)

type scannerFunc func(context.Context, []int) (portscan.Result, error)

func (f scannerFunc) Scan(ctx context.Context, ports []int) (portscan.Result, error) {
	return f(ctx, ports)
}

func TestScanSessionEnforcesLimitIncludingFailures(t *testing.T) {
	calls := 0
	failure := errors.New("scan failure")
	session, err := NewScanSession(scannerFunc(func(context.Context, []int) (portscan.Result, error) { calls++; return portscan.Result{}, failure }), []int{80})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < portscan.MaxScans; i++ {
		if _, err := session.Execute(context.Background(), portscan.Action{Reason: "test", Action: "scan_ports", Ports: []int{80}}); !errors.Is(err, failure) {
			t.Fatalf("got %v", err)
		}
	}
	if _, err := session.Execute(context.Background(), portscan.Action{Reason: "test", Action: "scan_ports", Ports: []int{80}}); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("expected limit, got %v", err)
	}
	if calls != portscan.MaxScans {
		t.Fatalf("executed %d scans", calls)
	}
}

func TestScanSessionRejectsBeforeExecution(t *testing.T) {
	session, err := NewScanSession(scannerFunc(func(context.Context, []int) (portscan.Result, error) {
		t.Fatal("invalid scan executed")
		return portscan.Result{}, nil
	}), []int{80})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []portscan.Action{{Reason: "test", Action: "finish"}, {Reason: "test", Action: "scan_ports", Ports: []int{0}}} {
		if _, err := session.Execute(context.Background(), action); err == nil {
			t.Fatal("invalid action accepted")
		}
	}
}

func TestScratchWorkflowPassesHistoryAndFinishes(t *testing.T) {
	calls := 0
	scanner := scannerFunc(func(_ context.Context, ports []int) (portscan.Result, error) {
		if len(ports) != 2 || ports[0] != 8080 || ports[1] != 8443 {
			t.Fatalf("unexpected ports %v", ports)
		}
		return portscan.Result{Hosts: []portscan.Host{{Ports: []portscan.Port{{Number: 8080, Protocol: "tcp", State: portscan.State{Value: "open"}}}}}}, nil
	})
	var output []any
	err := RunScratch(context.Background(), scanner, []int{8080}, func(input DecisionInput) (portscan.Action, error) {
		calls++
		if calls == 1 {
			return portscan.Action{Reason: "check", Action: "scan_ports", Ports: []int{8080, 8443}}, nil
		}
		if len(input.History) != 1 || input.History[0].Step != 1 || input.History[0].Result.Hosts[0].Ports[0].State.Value != "open" {
			t.Fatalf("unexpected history %+v", input.History)
		}
		return portscan.Action{Reason: "done", Action: "finish"}, nil
	}, func(value any) error { output = append(output, value); return nil })
	if err != nil || calls != 2 || len(output) != 2 {
		t.Fatalf("calls=%d output=%v err=%v", calls, output, err)
	}
}

func TestScratchWorkflowLimitsAndErrors(t *testing.T) {
	scanner := scannerFunc(func(context.Context, []int) (portscan.Result, error) { return portscan.Result{}, nil })
	next := func(DecisionInput) (portscan.Action, error) {
		return portscan.Action{Reason: "check", Action: "scan_ports", Ports: []int{80}}, nil
	}
	if err := RunScratch(context.Background(), scanner, []int{80}, next, func(any) error { return nil }); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("expected limit, got %v", err)
	}
	if err := RunScratch(context.Background(), scanner, []int{80}, next, func(any) error { return io.ErrClosedPipe }); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected output error, got %v", err)
	}
	failure := errors.New("decision failure")
	if err := RunScratch(context.Background(), scanner, []int{80}, func(DecisionInput) (portscan.Action, error) { return portscan.Action{}, failure }, func(any) error { return nil }); !errors.Is(err, failure) {
		t.Fatalf("expected decision error, got %v", err)
	}
}

func TestScratchRejectsPrematureFinishAndSuppliesPendingPorts(t *testing.T) {
	decisions, scans, finishes := 0, 0, 0
	scanner := scannerFunc(func(_ context.Context, ports []int) (portscan.Result, error) {
		scans++
		return portscan.Result{Hosts: []portscan.Host{{Ports: []portscan.Port{{Number: ports[0], Protocol: "tcp", State: portscan.State{Value: "closed"}}}}}}, nil
	})
	err := RunScratch(context.Background(), scanner, []int{8080, 8443}, func(input DecisionInput) (portscan.Action, error) {
		decisions++
		switch decisions {
		case 1:
			return portscan.Action{Reason: "premature", Action: "finish"}, nil
		case 2:
			if len(input.RequiredPorts) != 2 || len(input.PendingPorts) != 2 || !strings.Contains(input.Feedback, "finishを拒否") {
				t.Fatalf("missing requirements: %+v", input)
			}
			return portscan.Action{Reason: "check first", Action: "scan_ports", Ports: []int{8080}}, nil
		case 3:
			return portscan.Action{Reason: "still premature", Action: "finish"}, nil
		case 4:
			if len(input.PendingPorts) != 1 || input.PendingPorts[0] != 8443 {
				t.Fatalf("pending=%v", input.PendingPorts)
			}
			return portscan.Action{Reason: "check remaining", Action: "scan_ports", Ports: []int{8443}}, nil
		default:
			return portscan.Action{Reason: "done", Action: "finish"}, nil
		}
	}, func(value any) error {
		if a, ok := value.(portscan.Action); ok && a.Action == "finish" {
			finishes++
		}
		return nil
	})
	if err != nil || decisions != 5 || scans != 2 || finishes != 1 {
		t.Fatalf("decisions=%d scans=%d finishes=%d err=%v", decisions, scans, finishes, err)
	}
}

func TestScratchNeverFinishesWithMissingResults(t *testing.T) {
	calls := 0
	scanner := scannerFunc(func(context.Context, []int) (portscan.Result, error) { return portscan.Result{}, nil })
	err := RunScratch(context.Background(), scanner, []int{8443}, func(DecisionInput) (portscan.Action, error) {
		calls++
		if calls == 1 {
			return portscan.Action{Reason: "scan", Action: "scan_ports", Ports: []int{8443}}, nil
		}
		return portscan.Action{Reason: "premature", Action: "finish"}, nil
	}, func(value any) error {
		if _, ok := value.(portscan.Action); ok {
			t.Fatal("emitted premature finish")
		}
		return nil
	})
	if calls != 10 || err == nil || !strings.Contains(err.Error(), "8443") || !strings.Contains(err.Error(), "未完了") {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
