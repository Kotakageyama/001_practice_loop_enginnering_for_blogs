package portscan

import (
	"fmt"
	"strings"
)

const (
	Target   = "127.0.0.1"
	MaxPorts = 100
	MaxScans = 10
)

type Port struct {
	Number   int     `json:"port"`
	Protocol string  `json:"protocol"`
	State    State   `json:"state"`
	Service  Service `json:"service"`
}

type State struct {
	Value string `json:"value"`
}
type Service struct {
	Name string `json:"name"`
}
type Host struct {
	Ports []Port `json:"ports"`
}
type Result struct {
	Hosts []Host `json:"hosts"`
}

func ValidatePorts(ports []int) error {
	if len(ports) == 0 || len(ports) > MaxPorts {
		return fmt.Errorf("portsは1〜100件で指定してください")
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("ポートは1〜65535で指定してください")
		}
	}
	return nil
}

type Action struct {
	Reason string `json:"reason"`
	Action string `json:"action"`
	Ports  []int  `json:"ports,omitempty"`
}

func (a Action) Validate() error {
	if strings.TrimSpace(a.Reason) == "" {
		return fmt.Errorf("reasonは必須です")
	}
	switch a.Action {
	case "finish":
		if len(a.Ports) != 0 {
			return fmt.Errorf("finishにportsは指定できません")
		}
	case "scan_ports":
		return ValidatePorts(a.Ports)
	default:
		return fmt.Errorf("未対応のaction: %s", a.Action)
	}
	return nil
}
