package portscan

import "slices"

// Inspection holds one run's required ports and observed TCP results in memory.
type Inspection struct {
	required []int
	results  map[int]Port
}

func NewInspection(required []int) (*Inspection, error) {
	if err := ValidatePorts(required); err != nil {
		return nil, err
	}
	ports := slices.Clone(required)
	slices.Sort(ports)
	return &Inspection{required: slices.Compact(ports), results: make(map[int]Port)}, nil
}

func (i *Inspection) Required() []int { return slices.Clone(i.required) }

func (i *Inspection) Pending() []int {
	var pending []int
	for _, number := range i.required {
		p, ok := i.results[number]
		if !ok || (p.State.Value != "open" && p.State.Value != "closed") {
			pending = append(pending, number)
		}
	}
	return pending
}

func (i *Inspection) Record(requested []int, result Result) {
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.Protocol == "tcp" && slices.Contains(requested, port.Number) && slices.Contains(i.required, port.Number) {
				i.results[port.Number] = port
			}
		}
	}
}
