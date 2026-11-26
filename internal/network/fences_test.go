// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func TestListenerGenerationAcrossRestartAndDirectionalMTU(t *testing.T) {
	p, _ := NewPorts(2)
	l := Listener{ID: "http", Owner: "app", Generation: 1, Address: netip.IPv4Unspecified(), Protocol: 6, Port: 443}
	p, err := p.Reserve(l)
	if err != nil {
		t.Fatal(err)
	}
	p, err = p.Release(l)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(p.Checkpoint())
	var j PortJournal
	_ = json.Unmarshal(data, &j)
	p, err = RestorePorts(j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve(l); err == nil {
		t.Fatal("retired listener generation reused")
	}
	old := l
	l.Generation = 2
	p, err = p.Reserve(l)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Release(old); err == nil {
		t.Fatal("stale receipt removed replacement")
	}
	a := MTUObservation{From: "a", To: "b", Source: 9, Generation: 3, At: 90, PathMTU: 1500, Overhead: 100}
	b := a
	b.From, b.To = a.To, a.From
	if err := AdmitMTU(1400, 9, 3, 100, 10, a, b); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*MTUObservation){func(v *MTUObservation) { v.PathMTU = 1499 }, func(v *MTUObservation) { v.At = 89 }, func(v *MTUObservation) { v.At = 101 }, func(v *MTUObservation) { v.Source = 8 }, func(v *MTUObservation) { v.Generation = 2 }, func(v *MTUObservation) { v.From = "foreign" }} {
		bad := b
		mutate(&bad)
		if AdmitMTU(1400, 9, 3, 100, 10, a, bad) == nil {
			t.Fatal("invalid MTU evidence accepted", bad)
		}
	}
}
