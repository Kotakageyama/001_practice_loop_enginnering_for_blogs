package application

import (
	"context"
	"fmt"

	"pentest/internal/domain/portscan"
)

// Scanner is implemented by the external scanning adapter.
type Scanner interface {
	Scan(context.Context, []int) (portscan.Result, error)
}

type Observation struct {
	Step   int             `json:"step"`
	Action portscan.Action `json:"action"`
	Result portscan.Result `json:"result"`
}

// ScanSession counts attempts, including failed scans. Use it serially per workflow.
type ScanSession struct {
	scanner    Scanner
	inspection *portscan.Inspection
	calls      int
}

func NewScanSession(scanner Scanner, required []int) (*ScanSession, error) {
	inspection, err := portscan.NewInspection(required)
	if err != nil {
		return nil, err
	}
	return &ScanSession{scanner: scanner, inspection: inspection}, nil
}

func (s *ScanSession) Pending() []int { return s.inspection.Pending() }

func (s *ScanSession) CheckComplete() error {
	if pending := s.Pending(); len(pending) > 0 {
		return fmt.Errorf("検査未完了: 未確定の必須TCPポート %v", pending)
	}
	return nil
}

type DecisionInput struct {
	RequiredPorts []int         `json:"required_ports"`
	PendingPorts  []int         `json:"pending_ports"`
	History       []Observation `json:"history"`
	Feedback      string        `json:"feedback,omitempty"`
}

func (s *ScanSession) Execute(ctx context.Context, action portscan.Action) (Observation, error) {
	if err := action.Validate(); err != nil {
		return Observation{}, err
	}
	if action.Action != "scan_ports" {
		return Observation{}, fmt.Errorf("scan_portsのみ実行できます")
	}
	if s.calls >= portscan.MaxScans {
		return Observation{}, fmt.Errorf("スキャン回数の上限（10回）に達しました")
	}
	s.calls++
	result, err := s.scanner.Scan(ctx, action.Ports)
	if err != nil {
		return Observation{}, err
	}
	s.inspection.Record(action.Ports, result)
	return Observation{Step: s.calls, Action: action, Result: result}, nil
}

func RunScratch(ctx context.Context, scanner Scanner, required []int, next func(DecisionInput) (portscan.Action, error), emit func(any) error) error {
	session, err := NewScanSession(scanner, required)
	if err != nil {
		return err
	}
	var history []Observation
	var feedback string
	for step := 0; step < portscan.MaxScans; step++ {
		action, err := next(DecisionInput{RequiredPorts: session.inspection.Required(), PendingPorts: session.Pending(), History: history, Feedback: feedback})
		if err != nil {
			return err
		}
		if err := action.Validate(); err != nil {
			return err
		}
		if action.Action == "finish" {
			if err := session.CheckComplete(); err != nil {
				feedback = "finishを拒否しました: " + err.Error()
				continue
			}
			return emit(action)
		}
		observation, err := session.Execute(ctx, action)
		if err != nil {
			return err
		}
		history = append(history, observation)
		feedback = ""
		if err := emit(observation); err != nil {
			return err
		}
	}
	if err := session.CheckComplete(); err != nil {
		return fmt.Errorf("実行回数の上限（10回）: %w", err)
	}
	return fmt.Errorf("実行回数の上限（10回）に達しました")
}
