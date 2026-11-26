// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/ingress"
)

func (r *Runtime) ingressEvent(e ingress.Event) {
	if r.events == nil || e.Node == "" {
		return
	}
	scope := "node"
	if e.Tenant != "" {
		scope = "tenant"
		if e.App != "" {
			scope = "app"
		}
	}
	row := eventlog.Event{Kind: e.Kind, Scope: scope, At: e.ObservedAt, Target: eventlog.Target{Node: e.Node, Tenant: e.Tenant, App: e.App, Gateway: e.Gateway, RouteID: e.RouteID, Host: e.Host, Prefix: e.Prefix}, Detail: eventlog.Detail{Code: "INGRESS_OBSERVATION", Value: e.Value}}
	raw, _ := json.Marshal(row)
	tag := fmt.Sprintf("ingress/%x", sha256.Sum256(raw))
	if _, err := r.events.Append(tag, row, e.ObservedAt); err != nil {
		r.mu.Lock()
		r.moduleError = errors.Join(r.moduleError, err)
		r.mu.Unlock()
		r.wakeReport()
	}
}
