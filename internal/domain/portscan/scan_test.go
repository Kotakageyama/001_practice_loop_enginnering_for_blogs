package portscan

import "testing"

func TestActionValidation(t *testing.T) {
	for _, action := range []Action{
		{Reason: "test", Action: "scan_ports", Ports: []int{1, 65535}},
		{Reason: "done", Action: "finish"},
	} {
		if err := action.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []Action{
		{Action: "scan_ports", Ports: []int{80}},
		{Reason: " ", Action: "finish"},
		{Reason: "test", Action: "exec"},
		{Reason: "test", Action: "finish", Ports: []int{80}},
		{Reason: "test", Action: "scan_ports"},
		{Reason: "test", Action: "scan_ports", Ports: []int{0}},
		{Reason: "test", Action: "scan_ports", Ports: []int{65536}},
		{Reason: "test", Action: "scan_ports", Ports: make([]int, 101)},
	} {
		if err := action.Validate(); err == nil {
			t.Errorf("accepted %+v", action)
		}
	}
}
