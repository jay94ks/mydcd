// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"errors"
	"testing"
	"time"
)

func TestCertificateEventsReportScopedExpiryMissingAndRecovery(t *testing.T) {
	now := time.Now().Unix()
	m := &Manager{node: "node-a", certificateCache: map[string]certificateState{}}
	route := Route{ID: "shop", Host: "shop.example", Prefix: "/shop", Service: "web", Gateway: "external"}
	spec := Spec{Tenant: "tenant", App: "app", Listeners: []Listener{{ID: "https", TLS: true}}, Routes: []Route{route}}
	i := &instance{manager: m}
	var events []Event
	m.SetEventSink(func(e Event) { events = append(events, e) })
	set := func(after int64) {
		m.certificateCache["shop.example"] = certificateState{public: []CertificateObservation{{Host: route.Host, Fingerprint: [32]byte{1}, NotAfter: after}}}
	}
	// An expired certificate for another host must never change this route's
	// event, even when both hosts use the same shared listener.
	m.certificateCache["other.example"] = certificateState{public: []CertificateObservation{{Host: "other.example", NotAfter: now - 1}}}
	check := func(kind string) {
		t.Helper()
		if len(events) != 1 {
			t.Fatal("expected one transition", events)
		}
		e := events[0]
		if e.Kind != kind || e.Node != "node-a" || e.Tenant != spec.Tenant || e.App != spec.App || e.RouteID != route.ID || e.Host != route.Host || e.Prefix != route.Prefix || e.Gateway != route.Gateway || e.ObservedAt == 0 {
			t.Fatal("certificate event lost original route scope", e)
		}
		events = nil
	}
	set(now + 3600)
	i.certificateEvent(spec, route, nil)
	if len(events) != 1 || events[0].Value == 0 || events[0].Value > 3600 {
		t.Fatal("missing remaining lifetime", events)
	}
	check("cert-expiring")
	i.certificateEvent(spec, route, nil)
	if len(events) != 0 {
		t.Fatal("unchanged certificate emitted repeated event")
	}
	set(now - 1)
	i.certificateEvent(spec, route, errors.New("expired"))
	if len(events) != 1 || events[0].Value != 0 {
		t.Fatal("expired event retained an old lifetime", events)
	}
	check("cert-expired")
	m.certificateCache["shop.example"] = certificateState{}
	i.certificateEvent(spec, route, ErrCertificateWithdrawn)
	check("ingress-certificate-missing")
	set(now + 30*24*3600)
	i.certificateEvent(spec, route, nil)
	if len(events) != 0 {
		t.Fatal("healthy replacement emitted a failure")
	}
	set(now + 3600)
	i.certificateEvent(spec, route, nil)
	check("cert-expiring")
}
