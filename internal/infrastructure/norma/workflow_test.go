package norma

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pentest/internal/application"
	"pentest/internal/domain/portscan"
	"pentest/internal/infrastructure/nmap"

	"github.com/Autumn-27/norma/llm"
)

func TestNormaWorkflow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nmap"), []byte(`#!/bin/sh
[ "$*" = '-sT -Pn -n -p 8080,8443 -oX - 127.0.0.1' ] || exit 2
printf '%s' '<nmaprun><host><ports><port protocol="tcp" portid="8080"><state state="open"/></port><port protocol="tcp" portid="8443"><state state="closed"/></port></ports></host></nmaprun>'
`), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	calls := 0
	provider := normaTestProvider(t, func(r *http.Request) string {
		calls++
		var body struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			Input []struct {
				Type   string `json:"type"`
				CallID string `json:"call_id"`
				Output string `json:"output"`
			} `json:"input"`
			Store bool `json:"store"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Tools) != 1 || body.Tools[0].Name != "scan_ports" || body.Store {
			t.Fatalf("unexpected tools/storage: %+v", body)
		}
		if calls == 1 {
			return `{"status":"completed","output":[{"type":"function_call","call_id":"scan1","name":"scan_ports","arguments":"{\"reason\":\"HTTP用の別ポートを確認\",\"ports\":[8080,8443]}"}]}`
		}
		found := false
		for _, item := range body.Input {
			if item.Type == "function_call_output" && item.CallID == "scan1" && strings.Contains(item.Output, `"value":"open"`) {
				found = true
			}
		}
		if !found {
			t.Fatal("next decision did not receive nmap result")
		}
		return `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"8080がopenでした。確認完了。"}]}]}`
	})
	var out bytes.Buffer
	if err := Workflow(context.Background(), provider, "HTTP用の別ポートを確認", []int{8080, 8443}, nmap.Scanner{}, json.NewEncoder(&out).Encode); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(out.String(), `"action":"finish"`) || !strings.Contains(out.String(), `"port":8080`) {
		t.Fatalf("calls=%d output=%s", calls, out.String())
	}
}

func TestNormaScanToolValidation(t *testing.T) {
	for _, input := range []string{
		`{"reason":"test","ports":[80],"target":"example.com"}`,
		`{"reason":"test","ports":[80],"command":"id"}`,
		`{"reason":"test","ports":[0]}`,
		`{"reason":"test","ports":[65536]}`,
		`{"reason":"test","ports":[]}`,
		`{"ports":[80]}`,
		`{"reason":"test","ports":[80]} {}`,
	} {
		if _, err := scanTool(testScanSession(t), json.NewEncoder(io.Discard).Encode).Call(context.Background(), json.RawMessage(input), nil); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestNormaTurnLimit(t *testing.T) {
	provider := normaTestProvider(t, func(*http.Request) string {
		return `{"status":"completed","output":[{"type":"function_call","call_id":"bad","name":"Bash","arguments":"{\"command\":\"exit 1\"}"}]}`
	})
	if err := Workflow(context.Background(), provider, "test", []int{80}, nmap.Scanner{}, json.NewEncoder(io.Discard).Encode); err == nil || !strings.Contains(err.Error(), "max_turns") {
		t.Fatalf("expected turn limit, got %v", err)
	}
}

func normaTestProvider(t *testing.T, respond func(*http.Request) string) llm.Provider {
	t.Helper()
	provider, err := llm.NewProvider(llm.Config{
		Format: llm.FormatOpenAIResponses, BaseURL: "https://api.openai.com/v1", APIKey: "test-key", Model: "test-model", MaxRetries: -1,
		HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/v1/responses" {
				t.Errorf("unexpected URL: %s", r.URL)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respond(r))), Header: make(http.Header)}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testScanSession(t *testing.T) *application.ScanSession {
	t.Helper()
	session, err := application.NewScanSession(nmap.Scanner{}, []int{80})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

type scannerFunc func(context.Context, []int) (portscan.Result, error)

func (f scannerFunc) Scan(ctx context.Context, ports []int) (portscan.Result, error) {
	return f(ctx, ports)
}

func TestNormaRejectsEarlyFinishThenScansRemainingPorts(t *testing.T) {
	calls, scans := 0, 0
	scanner := scannerFunc(func(_ context.Context, ports []int) (portscan.Result, error) {
		scans++
		return portscan.Result{Hosts: []portscan.Host{{Ports: []portscan.Port{{Number: ports[0], Protocol: "tcp", State: portscan.State{Value: "closed"}}}}}}, nil
	})
	provider := normaTestProvider(t, func(r *http.Request) string {
		calls++
		switch calls {
		case 1:
			return `{"status":"completed","output":[{"type":"function_call","call_id":"s1","name":"scan_ports","arguments":"{\"reason\":\"first\",\"ports\":[8080]}"}]}`
		case 2:
			return `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"完了"}]}]}`
		case 3:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "8443") || !strings.Contains(string(body), "未完了") {
				t.Fatalf("missing feedback: %s", body)
			}
			return `{"status":"completed","output":[{"type":"function_call","call_id":"s2","name":"scan_ports","arguments":"{\"reason\":\"remaining\",\"ports\":[8443]}"}]}`
		default:
			return `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"両ポートを確認"}]}]}`
		}
	})
	var out bytes.Buffer
	err := Workflow(context.Background(), provider, "check", []int{8080, 8443}, scanner, json.NewEncoder(&out).Encode)
	if err != nil || calls != 4 || scans != 2 || strings.Count(out.String(), `"action":"finish"`) != 1 {
		t.Fatalf("calls=%d scans=%d err=%v out=%s", calls, scans, err, out.String())
	}
}

func TestNormaCannotFinishWithoutResolvedResults(t *testing.T) {
	for _, state := range []string{"missing", "filtered", "scan_error"} {
		t.Run(state, func(t *testing.T) {
			calls := 0
			scanner := scannerFunc(func(context.Context, []int) (portscan.Result, error) {
				if state == "scan_error" {
					return portscan.Result{}, context.DeadlineExceeded
				}
				if state == "missing" {
					return portscan.Result{}, nil
				}
				return portscan.Result{Hosts: []portscan.Host{{Ports: []portscan.Port{{Number: 8443, Protocol: "tcp", State: portscan.State{Value: "filtered"}}}}}}, nil
			})
			provider := normaTestProvider(t, func(*http.Request) string {
				calls++
				if calls == 1 {
					return `{"status":"completed","output":[{"type":"function_call","call_id":"s1","name":"scan_ports","arguments":"{\"reason\":\"check\",\"ports\":[8443]}"}]}`
				}
				return `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"完了"}]}]}`
			})
			var out bytes.Buffer
			err := Workflow(context.Background(), provider, "check", []int{8443}, scanner, json.NewEncoder(&out).Encode)
			if err == nil || !strings.Contains(err.Error(), "8443") || strings.Contains(out.String(), `"action":"finish"`) {
				t.Fatalf("err=%v out=%s", err, out.String())
			}
		})
	}
}
