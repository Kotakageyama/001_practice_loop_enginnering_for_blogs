package openai

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
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOpenAIAndNmapLoop(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nmap"), []byte(`#!/bin/sh
[ "$*" = '-sT -Pn -n -p 8080,8443 -oX - 127.0.0.1' ] || exit 2
printf '%s' '<nmaprun><host><ports><port protocol="tcp" portid="8080"><state state="open"/></port><port protocol="tcp" portid="8443"><state state="closed"/></port></ports></host></nmaprun>'
`), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	calls := 0
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.openai.com/v1/responses" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatal("unexpected API request")
		}
		var request struct {
			Input string `json:"input"`
			Store bool   `json:"store"`
			Text  struct {
				Format struct {
					Type   string `json:"type"`
					Strict bool   `json:"strict"`
				} `json:"format"`
			} `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Store || request.Text.Format.Type != "json_schema" || !request.Text.Format.Strict {
			t.Fatal("invalid request configuration")
		}
		var input struct {
			Goal    string                    `json:"goal"`
			History []application.Observation `json:"history"`
		}
		if err := json.Unmarshal([]byte(request.Input), &input); err != nil {
			t.Fatal(err)
		}
		if input.Goal != "HTTP用の別ポートを確認" || len(input.History) != calls-1 {
			t.Fatalf("missing history: %+v", input)
		}
		action := portscan.Action{Reason: "HTTP用の別ポートを確認したい", Action: "scan_ports", Ports: []int{8080, 8443}}
		if calls == 2 {
			if input.History[0].Result.Hosts[0].Ports[0].State.Value != "open" {
				t.Fatal("missing nmap result")
			}
			action = portscan.Action{Reason: "8080はopen、確認完了", Action: "finish", Ports: []int{}}
		}
		data, _ := json.Marshal(action)
		body, _ := json.Marshal(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": string(data)}}}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	var out bytes.Buffer
	err := application.RunScratch(context.Background(), nmap.Scanner{}, []int{8080, 8443}, func(decision application.DecisionInput) (portscan.Action, error) {
		return (Client{HTTP: client, APIKey: "test-key", Model: "test-model"}).Decide(context.Background(), "HTTP用の別ポートを確認", decision)
	}, json.NewEncoder(&out).Encode)
	if err != nil || calls != 2 || !strings.Contains(out.String(), `"action":"finish"`) {
		t.Fatalf("calls=%d, err=%v, output=%s", calls, err, out.String())
	}
}

func TestNextActionRejectsBadResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"API error", 401, `secret`},
		{"bad JSON", 200, `{`},
		{"incomplete", 200, `{"status":"incomplete"}`},
		{"refusal", 200, `{"status":"completed","output":[{"type":"message","content":[{"type":"refusal"}]}]}`},
		{"empty", 200, `{"status":"completed","output":[]}`},
		{"invalid action", 200, `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"{\"reason\":\"test\",\"action\":\"exec\"}"}]}]}`},
		{"extra field", 200, `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"{\"reason\":\"test\",\"action\":\"finish\",\"target\":\"other\"}"}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}
			if _, err := (Client{HTTP: client, APIKey: "test-key", Model: "test-model"}).Decide(context.Background(), "goal", application.DecisionInput{}); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
