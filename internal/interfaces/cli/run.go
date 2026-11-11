package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pentest/internal/application"
	"pentest/internal/domain/portscan"
	"pentest/internal/infrastructure/nmap"
	"pentest/internal/infrastructure/norma"
	"pentest/internal/infrastructure/openai"
)

type Config struct {
	APIKey string
	Model  string
}

func Run(ctx context.Context, args []string, config Config, out io.Writer) error {
	scanner := nmap.Scanner{}
	encoder := json.NewEncoder(out)
	if len(args) > 0 && (args[0] == "--agent" || args[0] == "--scratch") {
		if len(args) != 4 || args[2] != "--ports" {
			return fmt.Errorf("使い方: pentest %s 調査目的 --ports 8080,8443", args[0])
		}
		required, err := parsePorts(args[3])
		if err != nil {
			return err
		}
		goal := args[1]
		if config.APIKey == "" || config.Model == "" || strings.TrimSpace(goal) == "" {
			return fmt.Errorf("OPENAI_API_KEY、OPENAI_MODELと空でない調査目的を指定してください")
		}
		if args[0] == "--agent" {
			return norma.Run(ctx, config.APIKey, config.Model, goal, required, scanner, encoder.Encode)
		}
		client := openai.Client{APIKey: config.APIKey, Model: config.Model, HTTP: &http.Client{Timeout: 60 * time.Second}}
		return application.RunScratch(ctx, scanner, required, func(decision application.DecisionInput) (portscan.Action, error) {
			return client.Decide(ctx, goal, decision)
		}, encoder.Encode)
	}
	if len(args) != 1 || args[0] != portscan.Target {
		return fmt.Errorf("対象は127.0.0.1のみ（使い方: pentest 127.0.0.1 | --agent 調査目的 | --scratch 調査目的）")
	}
	result, err := scanner.Scan(ctx, []int{22, 80, 443, 8080})
	if err != nil {
		return err
	}
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func parsePorts(value string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("--portsはポート番号をカンマ区切りで指定してください")
		}
		ports = append(ports, port)
	}
	return ports, portscan.ValidatePorts(ports)
}
