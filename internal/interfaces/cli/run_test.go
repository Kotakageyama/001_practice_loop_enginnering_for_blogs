package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"pentest/internal/domain/portscan"
)

func TestRunRejectsTarget(t *testing.T) {
	for _, args := range [][]string{nil, {"example.com"}, {"127.0.0.1", "-p", "1-65535"}} {
		if err := Run(context.Background(), args, Config{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestFixedScanOutput(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
[ "$*" = '-sT -Pn -n -p 22,80,443,8080 -oX - 127.0.0.1' ] || exit 2
printf '%s' '<nmaprun><host><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port></ports></host></nmaprun>'
`
	if err := os.WriteFile(filepath.Join(dir, "nmap"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"127.0.0.1"}, Config{}, &out); err != nil {
		t.Fatal(err)
	}
	var result portscan.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || len(result.Hosts[0].Ports) != 1 || result.Hosts[0].Ports[0].Number != 8080 {
		t.Fatalf("unexpected JSON: %s", out.String())
	}
}

func TestAgentConfiguration(t *testing.T) {
	for _, mode := range []string{"--agent", "--scratch"} {
		for _, config := range []Config{{}, {APIKey: "key"}, {Model: "model"}} {
			if err := Run(context.Background(), []string{mode, "goal", "--ports", "8080,8443"}, config, &bytes.Buffer{}); err == nil {
				t.Fatal("missing configuration accepted")
			}
		}
		if err := Run(context.Background(), []string{mode, " ", "--ports", "8080,8443"}, Config{APIKey: "key", Model: "model"}, &bytes.Buffer{}); err == nil {
			t.Fatal("empty goal accepted")
		}
	}
}

func TestAgentRequiresExplicitValidPorts(t *testing.T) {
	for _, mode := range []string{"--agent", "--scratch"} {
		for _, args := range [][]string{
			{mode, "8080を確認"},
			{mode, "goal", "--ports", ""},
			{mode, "goal", "--ports", "0"},
			{mode, "goal", "--ports", "65536"},
			{mode, "goal", "--ports", "8080;id"},
			{mode, "goal", "--ports", "8080,"},
		} {
			if err := Run(context.Background(), args, Config{APIKey: "test", Model: "test"}, &bytes.Buffer{}); err == nil {
				t.Fatalf("accepted %v", args)
			}
		}
	}
}
