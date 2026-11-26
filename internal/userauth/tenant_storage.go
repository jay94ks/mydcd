// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"reflect"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (r Request) validTenantStorageFields() bool {
	if r.Method != "tenant-storage" {
		return true
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, Node: r.Node, After: r.After}
	return lifecycle.ValidID(r.Tenant) && (r.Node == "" || lifecycle.ValidID(r.Node)) && len(r.After) <= 512 && reflect.DeepEqual(r, want)
}
func (c Client) TenantStoragePage(ctx context.Context, target mydcp.Peer, session access.Session, tenant, node, after string) (Reply, error) {
	request := Request{Method: "tenant-storage", Tenant: tenant, Node: node, After: after}
	if !request.validTenantStorageFields() {
		return Reply{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, request)
	if err != nil {
		return reply, err
	}
	if reply.TenantStorageViewIndex == 0 || len(reply.TenantStorage) > 8 || len(reply.TenantStorageNext) > 512 {
		return Reply{}, mydcp.ErrFrame
	}
	previous := ""
	for _, root := range reply.TenantStorage {
		key := root.Node + "/" + root.ID
		if !root.Allowed || root.Revision == 0 || root.Generation == 0 || root.Root.Validate() != nil || root.Root.Cluster != c.Cluster || root.Node != root.Root.Node || root.ID != root.Root.ID || root.Generation != root.Root.Generation || node != "" && root.Node != node || previous != "" && key <= previous {
			return Reply{}, mydcp.ErrFrame
		}
		previous = key
	}
	if reply.TenantStorageNext != "" && (len(reply.TenantStorage) == 0 || reply.TenantStorageNext == after) {
		return Reply{}, mydcp.ErrFrame
	}
	return reply, nil
}
