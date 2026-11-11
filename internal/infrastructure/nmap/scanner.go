package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"pentest/internal/domain/portscan"
)

type Scanner struct{}

type xmlPort struct {
	Number   int    `xml:"portid,attr"`
	Protocol string `xml:"protocol,attr"`
	State    struct {
		Value string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name string `xml:"name,attr"`
	} `xml:"service"`
}

type xmlResult struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Ports []xmlPort `xml:"ports>port"`
	} `xml:"host"`
}

func (Scanner) Scan(ctx context.Context, ports []int) (portscan.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var result portscan.Result
	if err := portscan.ValidatePorts(ports); err != nil {
		return result, err
	}
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}
	cmd := exec.CommandContext(ctx, "nmap",
		"-sT", "-Pn", "-n", "-p", strings.Join(values, ","), "-oX", "-", portscan.Target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return result, fmt.Errorf("Nmap実行中断: %w", ctx.Err())
		}
		return result, fmt.Errorf("Nmap実行失敗: %w: %s", err, stderr.String())
	}
	var wire xmlResult
	if err := xml.Unmarshal(stdout.Bytes(), &wire); err != nil {
		return result, fmt.Errorf("XML解析失敗: %w", err)
	}
	for _, host := range wire.Hosts {
		h := portscan.Host{}
		for _, p := range host.Ports {
			h.Ports = append(h.Ports, portscan.Port{Number: p.Number, Protocol: p.Protocol, State: portscan.State{Value: p.State.Value}, Service: portscan.Service{Name: p.Service.Name}})
		}
		result.Hosts = append(result.Hosts, h)
	}
	return result, nil
}
