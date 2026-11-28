// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// LogKeeps returns a resolver for the x-sfc.logs.keep that applies to a
// stored log by its tenant, internal app scope and service: the service's,
// else the app's, from the app's current document. It answers "" for an
// app (or standalone) that no longer has a record or a retained document;
// node.yaml logs.keep applies then. Nothing here is a Raft change.
func (p Policy) LogKeeps(s state.State) (func(tenant, scope, service string) string, error) {
	p, err := p.Current(s)
	if err != nil {
		return nil, err
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return nil, err
	}
	parsed := map[string]*deployment.Compose{}
	return func(tenant, scope, service string) string {
		key := appKey(tenant, scope)
		c, seen := parsed[key]
		if !seen {
			parsed[key] = nil
			if e, ok := apps.entries[key]; ok {
				if x, ok := e.Inventory.Execution(); ok {
					if doc := x.Blueprint().OriginalDocument(); doc != nil {
						parse := deployment.ParseCompose
						if e.Standalone != nil {
							parse = deployment.ParseStandalone
						}
						if got, err := parse(doc.Body); err == nil {
							c = &got
							parsed[key] = c
						}
					}
				}
			}
		}
		if c == nil {
			return ""
		}
		return c.LogKeep(service)
	}, nil
}
