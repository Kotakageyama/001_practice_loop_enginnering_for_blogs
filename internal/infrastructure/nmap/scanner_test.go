package nmap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanner(t *testing.T) {
	for _, tc := range []struct {
		name, script, wantError string
	}{
		{"success", `
[ "$*" = '-sT -Pn -n -p 22,80,443,8080 -oX - 127.0.0.1' ] || exit 2
printf '%s' '<nmaprun><host><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port></ports></host></nmaprun>'
`, ""},
		{"command failure", "echo failed >&2; exit 1", "Nmap実行失敗"},
		{"invalid XML", "echo broken", "XML解析失敗"},
		{"wrong XML root", "echo '<other/>'", "XML解析失敗"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "nmap"), []byte("#!/bin/sh\n"+tc.script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			result, err := (Scanner{}).Scan(context.Background(), []int{22, 80, 443, 8080})
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("got %v, want %s", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Hosts) != 1 || len(result.Hosts[0].Ports) != 1 {
				t.Fatalf("unexpected result: %+v", result)
			}
			port := result.Hosts[0].Ports[0]
			if port.Number != 8080 || port.Protocol != "tcp" || port.State.Value != "open" || port.Service.Name != "http-proxy" {
				t.Fatalf("unexpected port: %+v", port)
			}
		})
	}
}

func TestScannerRejectsInvalidPortsBeforeCommand(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, ports := range [][]int{nil, {0}, {65536}, make([]int, 101)} {
		if _, err := (Scanner{}).Scan(context.Background(), ports); err == nil || strings.Contains(err.Error(), "Nmap") {
			t.Fatalf("expected validation error, got %v", err)
		}
	}
}
