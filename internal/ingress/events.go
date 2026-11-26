// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"fmt"
	"time"
)

func (i *instance) availabilityEvents() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.availability == nil {
		i.availability = map[string]bool{}
	}
	now := uint64(time.Now().UnixMilli())
	s := i.record.Spec
	for _, route := range s.Routes {
		j := i.record.Balances[route.Service]
		available := false
		for _, b := range j.Backends {
			available = available || b.Spec.Healthy && !b.Spec.Draining && b.Spec.ObservedAt <= now && now-b.Spec.ObservedAt <= j.MaxAge
		}
		prior, known := i.availability[route.ID]
		if known && prior == available {
			continue
		}
		i.availability[route.ID] = available
		if !known && available {
			continue
		}
		kind := "ingress-backends-empty"
		if available {
			kind = "ingress-backends-restored"
		}
		i.manager.emit(Event{Kind: kind, Tenant: s.Tenant, App: s.App, RouteID: route.ID, Host: route.Host, Prefix: route.Prefix, Gateway: route.Gateway, Value: uint64(boolInt(available))})
	}
}
func (i *instance) certificateEvent(s Spec, r Route, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.certificateFailures == nil {
		i.certificateFailures = map[string]string{}
	}
	kind, state := "", ""
	var value uint64
	if err != nil {
		kind, state = "ingress-certificate-missing", "missing"
	}
	now := time.Now().Unix()
	for _, certificate := range i.manager.certificateObservations(s) {
		if certificate.Host != r.Host {
			continue
		}
		if certificate.NotAfter > 0 && certificate.NotAfter <= now {
			kind, state = "cert-expired", fmt.Sprintf("expired:%x", certificate.Fingerprint)
			break
		}
		if certificate.NotAfter > now && certificate.NotAfter-now <= 7*24*3600 {
			kind, state = "cert-expiring", fmt.Sprintf("expiring:%x", certificate.Fingerprint)
			value = uint64(certificate.NotAfter - now)
		}
	}
	if state == "" {
		delete(i.certificateFailures, r.ID)
		return
	}
	if i.certificateFailures[r.ID] == state {
		return
	}
	i.certificateFailures[r.ID] = state
	i.manager.emit(Event{Kind: kind, Tenant: s.Tenant, App: s.App, RouteID: r.ID, Host: r.Host, Prefix: r.Prefix, Gateway: r.Gateway, Value: value})
}
