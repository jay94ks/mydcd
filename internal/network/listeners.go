// SPDX-License-Identifier: Apache-2.0

package network

// Ports retains generation floors after release. The lower-level slice helpers
// only detect simultaneous bind conflicts; this registry also fences old calls.
type Ports struct {
	current []Listener
	floors  map[string]uint64
	limit   int
}
type PortJournal struct {
	Schema  uint8
	Limit   int
	Current []Listener
	Floors  map[string]uint64
}

func NewPorts(limit int) (Ports, error) {
	if limit <= 0 {
		return Ports{}, ErrPolicy
	}
	return Ports{floors: map[string]uint64{}, limit: limit}, nil
}
func (p Ports) copy() Ports {
	q := p
	q.current = append([]Listener(nil), p.current...)
	q.floors = map[string]uint64{}
	for k, v := range p.floors {
		q.floors[k] = v
	}
	return q
}
func (p Ports) Reserve(l Listener) (Ports, error) {
	existing := false
	for _, old := range p.current {
		if old.ID == l.ID {
			existing = true
		}
	}
	if !existing && l.Generation <= p.floors[l.ID] {
		return p, ErrPolicy
	}
	current, err := ReserveListener(p.current, l, p.limit)
	if err != nil {
		return p, err
	}
	q := p.copy()
	q.current = current
	q.floors[l.ID] = l.Generation
	return q, nil
}
func (p Ports) Release(l Listener) (Ports, error) {
	current, err := ReleaseListener(p.current, l)
	if err != nil {
		return p, err
	}
	q := p.copy()
	q.current = current
	return q, nil
}
func (p Ports) Checkpoint() PortJournal {
	q := p.copy()
	return PortJournal{1, q.limit, q.current, q.floors}
}
func RestorePorts(j PortJournal) (Ports, error) {
	p, err := NewPorts(j.Limit)
	if err != nil || j.Schema != 1 {
		return Ports{}, ErrPolicy
	}
	for _, l := range j.Current {
		if p.floors[l.ID] != 0 {
			return Ports{}, ErrPolicy
		}
		p, err = p.Reserve(l)
		if err != nil {
			return Ports{}, err
		}
	}
	for id, g := range j.Floors {
		if id == "" || g == 0 || p.floors[id] != 0 && p.floors[id] != g {
			return Ports{}, ErrPolicy
		}
		p.floors[id] = g
	}
	for _, l := range p.current {
		if j.Floors[l.ID] != l.Generation {
			return Ports{}, ErrPolicy
		}
	}
	return p, nil
}

type MTUObservation struct {
	From, To               string
	Source, Generation, At uint64
	PathMTU, Overhead      int
}

// AdmitMTU uses two already signature-verified direction-specific observations.
// The signed source/generation/time belongs to the proposal, never FSM wall time.
func AdmitMTU(tun int, source, generation, now, maxAge uint64, a, b MTUObservation) error {
	if source == 0 || generation == 0 || maxAge == 0 || a.From == "" || a.To == "" || a.From == a.To || a.From != b.To || a.To != b.From {
		return ErrPolicy
	}
	for _, v := range []MTUObservation{a, b} {
		if v.Source != source || v.Generation != generation || v.At > now || now-v.At > maxAge {
			return ErrPolicy
		}
		budget, err := PacketBudget(tun, v.PathMTU, v.Overhead)
		if err != nil || budget < tun {
			return ErrPolicy
		}
	}
	return nil
}
