// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/binary"
	"slices"
)

// REQ-22 seed in the fake: instances and gateways (the source of the real
// `ingresses` mappings, fake_ingress_real.go) and the metric generator.

type ingressState struct {
	instances []IngressInstance
	gateways  map[string][]IngressGateway // node → gateways
	// REQ-22 E/F (mock): gateway revisions and the change history.
	nodeAddrs map[string][]string // Fixture.NodeAddresses
}

func (w *world) seedIngress(f Fixture) {
	w.ing = ingressState{gateways: map[string][]IngressGateway{}, nodeAddrs: map[string][]string{}}
	for n, a := range f.NodeAddresses {
		w.ing.nodeAddrs[n] = slices.Clone(a)
	}
	for _, in := range f.Ingresses {
		w.ing.instances = append(w.ing.instances, cloneInstance(in))
	}
	for n, gs := range f.IngressGateways {
		w.ing.gateways[n] = slices.Clone(gs)
	}
}

func cloneInstance(in IngressInstance) IngressInstance {
	in.Listeners = slices.Clone(in.Listeners)
	for i := range in.Listeners {
		in.Listeners[i].Protocols = slices.Clone(in.Listeners[i].Protocols)
	}
	in.Routes = slices.Clone(in.Routes)
	in.Backends = slices.Clone(in.Backends)
	in.Blocks = slices.Clone(in.Blocks)
	return in
}

func seed(s string) uint64 {
	d := digestOf([]byte(s))
	return binary.BigEndian.Uint64(d[:8])
}

func metricSets(key string, blocked, unhealthy bool) []IngressMetricSet {
	s := seed(key)
	rate := 2 + float64(s%400)/10
	var out []IngressMetricSet
	for _, win := range []struct {
		name string
		secs float64
	}{{"1m", 60}, {"5m", 300}, {"1h", 3600}} {
		total := uint64(rate * win.secs)
		set := IngressMetricSet{Window: win.name, RatePerSec: rate, P50MS: 8 + float64(s%30), P95MS: 40 + float64(s%120), P99MS: 120 + float64(s%400),
			Connections: 3 + int(s%40), BytesIn: total * 900, BytesOut: total * 14000}
		switch {
		case blocked:
			set.Blocked, set.C2xx = total, 0
		default:
			set.C4xx, set.C3xx = total/50, total/100
			set.C5xx = total / 500
			if unhealthy {
				set.C5xx = total / 10
				set.ProxyFailures = map[string]uint64{"connect": total / 20, "timeout": total / 40}
			}
			set.C2xx = total - set.C4xx - set.C3xx - set.C5xx
		}
		out = append(out, set)
	}
	return out
}
