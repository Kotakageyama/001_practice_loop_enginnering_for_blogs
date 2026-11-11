package portscan

import (
	"reflect"
	"testing"
)

func TestInspectionTracksOnlyResolvedRequestedTCPPorts(t *testing.T) {
	required := []int{8443, 8080, 8080}
	inspection, err := NewInspection(required)
	if err != nil {
		t.Fatal(err)
	}
	required[0] = 80
	snapshot := inspection.Required()
	snapshot[0] = 1
	if !reflect.DeepEqual(inspection.Required(), []int{8080, 8443}) {
		t.Fatal("required ports were mutated")
	}
	for _, tc := range []struct {
		name      string
		requested []int
		ports     []Port
		pending   []int
	}{
		{"missing", []int{8080, 8443}, nil, []int{8080, 8443}},
		{"UDP ignored", []int{8080}, []Port{{Number: 8080, Protocol: "udp", State: State{Value: "open"}}}, []int{8080, 8443}},
		{"unrequested ignored", []int{80}, []Port{{Number: 8080, Protocol: "tcp", State: State{Value: "open"}}}, []int{8080, 8443}},
		{"filtered unresolved", []int{8080}, []Port{{Number: 8080, Protocol: "tcp", State: State{Value: "filtered"}}}, []int{8080, 8443}},
		{"open recorded", []int{8080}, []Port{{Number: 8080, Protocol: "tcp", State: State{Value: "open"}}}, []int{8443}},
		{"closed recorded", []int{8443}, []Port{{Number: 8443, Protocol: "tcp", State: State{Value: "closed"}}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspection.Record(tc.requested, Result{Hosts: []Host{{Ports: tc.ports}}})
			if got := inspection.Pending(); !reflect.DeepEqual(got, tc.pending) {
				t.Fatalf("pending=%v want=%v", got, tc.pending)
			}
		})
	}
}

func TestInspectionRequiresValidPorts(t *testing.T) {
	for _, ports := range [][]int{nil, {0}, {65536}, make([]int, 101)} {
		if _, err := NewInspection(ports); err == nil {
			t.Fatalf("accepted %v", ports)
		}
	}
}
