// SPDX-License-Identifier: Apache-2.0

//go:build linux

package services

import (
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"strings"
)

func (o *DNSOwner) Activity() (lifecycle.Activity, error) { return o.TenantActivity("") }

func (o *DNSOwner) TenantActivity(tenant string) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	if !o.mu.TryLock() {
		activity.Resources = 1
		return activity, nil
	}
	defer o.mu.Unlock()
	if o.closed || o.failed {
		return activity, ErrLease
	}
	for _, query := range o.dns.Queries() {
		if tenant == "" || strings.HasPrefix(query.scope, tenant+"/") {
			activity.Flows++
		}
	}
	for _, group := range o.sockets {
		if tenant != "" && group.tenant != tenant {
			continue
		}
		group.mu.Lock()
		if !group.closed || !group.joined {
			activity.Resources++
		}
		group.mu.Unlock()
	}
	return activity, nil
}
