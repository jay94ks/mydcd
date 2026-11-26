// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// cpuUnit is workload.Resources.CPU per core (the task recipe hands it to
// Docker as NanoCPUs).
const cpuUnit = 1e9

// fakeNodeKey stands in for the node's work key (workNodeOwner): the public
// half of FixtureKey(node), so owner-signed proofs verify.
func fakeNodeKey(node string) [32]byte { return pub32(FixtureKey(node)) }

// retirementRemaining: what still blocks finishing a tenant retirement in
// the fake (its apps and volumes).
func (w *world) retirementRemaining(tenant string) []string {
	var out []string
	for _, k := range sortedKeys(w.apps) {
		if a := w.apps[k]; a.view.Tenant == tenant {
			out = append(out, "app/"+a.view.App)
		}
	}
	for _, v := range w.volumes {
		if v.Tenant == tenant {
			out = append(out, "volume/"+v.Name)
		}
	}
	return out
}

// applyTenantRetirement models begin/finish-tenant-retirement with the
// catalog rules (access.Catalog Begin/FinishTenantRetirement). f.mu is held.
func (c *fakeConn) applyTenantRetirement(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var v control.TenantRetirementSelection
	if decodePayload(ch.Payload, &v) != nil || v.Tenant == "" || v.Operation == "" {
		return errors.New("payload")
	}
	if !w.admin(actor) {
		return errForbidden
	}
	if _, ok := w.tenants[v.Tenant]; !ok || w.tenantRev[v.Tenant] != ch.Expected {
		return errCAS
	}
	cur, retiring := w.retiring[v.Tenant]
	if ch.Action == ActionBeginTenantRetirement {
		if retiring || w.retired[v.Tenant] {
			return errors.New("not active")
		}
		w.retiring[v.Tenant] = v.Operation
	} else {
		if !retiring || cur != v.Operation || len(w.retirementRemaining(v.Tenant)) != 0 {
			return errors.New("not finishable")
		}
		delete(w.retiring, v.Tenant)
		w.retired[v.Tenant] = true
	}
	w.tenantRev[v.Tenant] = next
	return nil
}
