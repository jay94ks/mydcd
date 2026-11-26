// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// --- REQ-33 ---
//
// The closure reads the member rows of fake_network_change.go (drain-network
// lives there); fence-network-change and leave-tun-network check the closure
// with memberClosureOK.

// networkUsers: app services whose current definition names the network
// and standalone containers on it; node "" = every server.
func (w *world) networkUsers(tenant, network, node string) []NetworkUser {
	var out []NetworkUser
	for _, k := range sortedKeys(w.apps) {
		a := w.apps[k]
		if a.view.Tenant != tenant || a.view.Retiring || len(a.sources) == 0 {
			continue
		}
		d, err := parseApp(a.sources[len(a.sources)-1].Document)
		if err != nil {
			continue
		}
		for _, svc := range sortedKeys(d.Services) {
			s := d.Services[svc]
			if !slices.Contains(networkNames(s.Networks), network) || node != "" && s.XMydc.Node != node {
				continue
			}
			u := NetworkUser{Kind: NetworkUserService, App: a.view.App, Service: svc, Node: s.XMydc.Node}
			for _, t := range a.tasks {
				if t.Service == svc && t.Observed != "exited" && (node == "" || t.Node == node) {
					u.Selection = append(u.Selection, ContainerSelection{App: t.App, Service: t.Service, Instance: t.Instance})
				}
			}
			u.Attached = len(u.Selection) > 0
			out = append(out, u)
		}
	}
	for _, k := range sortedKeys(w.standalones) {
		e := w.standalones[k]
		if e.view.Tenant != tenant || e.removed() || !slices.Contains(e.spec.Networks, network) || node != "" && e.view.Node != node {
			continue
		}
		u := NetworkUser{Kind: NetworkUserStandalone, Standalone: e.view.Name, Node: e.view.Node, Attached: e.view.State == "running"}
		if u.Attached {
			u.Selection = []ContainerSelection{{Standalone: e.view.Name}}
		}
		out = append(out, u)
	}
	return out
}

// networkEndpoints lists running containers on node that use the network.
func (w *world) networkEndpoints(tenant, network, node string) []ContainerSelection {
	var out []ContainerSelection
	for _, u := range w.networkUsers(tenant, network, node) {
		out = append(out, u.Selection...)
	}
	return out
}

func countUsers(us []NetworkUser) (apps, standalones int) {
	seen := map[string]bool{}
	for _, u := range us {
		if u.Kind == NetworkUserStandalone {
			standalones++
		} else if !seen[u.App] {
			seen[u.App] = true
			apps++
		}
	}
	return apps, standalones
}

// networkUsers: the REQ-35 network-users rows PublicRead pages.
func (c *fakeConn) networkUsers(ctx context.Context, tenant, network string) (NetworkUsers, error) {
	const m = "network-users"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return NetworkUsers{}, err
	}
	defer c.unlock()
	w := c.f.w
	if i, _ := w.networkRow(tenant, network); i < 0 {
		return NetworkUsers{}, fail(m, CodeMissing, "")
	}
	v := NetworkUsers{Tenant: tenant, Network: network, Users: w.networkUsers(tenant, network, ""), ObservedAt: c.f.now().Unix()}
	v.Apps, v.Standalones = countUsers(v.Users)
	return v, nil
}

// memberClosure is what the member's owner would sign now: nil while the
// member is not draining or a container still uses it.
func (w *world) memberClosure(tenant, network string, m NetworkMember) ([]ContainerSelection, *NetworkClosure) {
	eps := w.networkEndpoints(tenant, network, m.Node)
	if !m.Draining || len(eps) > 0 {
		return eps, nil
	}
	p := tenancy.NetworkClosure{Cluster: w.cluster, Tenant: tenant, Network: m.ID, Node: m.Node, Owner: m.Source.Owner,
		Generation: m.Source.Generation, Revision: m.Source.Revision, NativeGone: true}
	p.Signature = ed25519.Sign(FixtureKey(m.Node), tenancy.NetworkClosureBytes(p))
	return nil, &p
}

// memberClosureOK: the checks of tenancy validSourceClose / Retire on the
// fake member row.
func (w *world) memberClosureOK(tenant string, m NetworkMember, p NetworkClosure) bool {
	return m.Draining && p.Cluster == w.cluster && p.Tenant == tenant && p.Network == m.ID && p.Node == m.Node &&
		p.Owner == m.Source.Owner && p.Generation == m.Source.Generation && p.Revision == m.Source.Revision &&
		p.NativeGone && p.PendingEndpoints == 0 && p.PendingFlows == 0 && p.PendingPins == 0 &&
		ed25519.Verify(ed25519.PublicKey(p.Owner[:]), tenancy.NetworkClosureBytes(p), p.Signature)
}

// networkClosure: the network-closure row PublicRead returns.
func (c *fakeConn) networkClosure(ctx context.Context, tenant, member string) (NetworkClosureView, error) {
	const m = "network-closure"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return NetworkClosureView{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(c.session.User, tenant) {
		return NetworkClosureView{}, fail(m, CodeDenied, "")
	}
	i, row, j := w.memberByID(tenant, member)
	if i < 0 {
		return NetworkClosureView{}, fail(m, CodeMissing, "")
	}
	mem := row.Members[j]
	v := NetworkClosureView{Tenant: tenant, Network: mem.ID, Node: mem.Node, Draining: mem.Draining, ObservedAt: c.f.now().Unix()}
	if w.memberPhase(mem.Node) != string(NodePhaseActive) {
		v.Unreachable = true
		return v, nil
	}
	v.Endpoints, v.Closed = w.memberClosure(tenant, row.Name, mem)
	v.PendingEndpoints = uint64(len(v.Endpoints))
	v.NativeGone = v.Closed != nil
	return v, nil
}

// applyFenceNetworkChange: control.NetworkChangeFence; Expected = the
// change Revision, Generation = the change Generation.
func (c *fakeConn) applyFenceNetworkChange(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	var q control.NetworkChangeFence
	if decodePayload(op.Change.Payload, &q) != nil || q.Closed.Tenant != q.Tenant || q.Closed.Network != q.ID {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	i, row, j := w.memberByID(q.Tenant, q.ID)
	if i < 0 {
		return errCAS
	}
	m := &row.Members[j]
	if m.Change == nil || m.Change.Phase != string(tenancy.ChangeDraining) || m.Change.Generation != q.Generation || m.Change.Revision != op.Change.Expected {
		return errCAS
	}
	if !w.memberClosureOK(q.Tenant, *m, q.Closed) {
		return errors.New("closure")
	}
	m.Change.Phase, m.Change.Revision = string(tenancy.ChangeFenced), next
	w.resources[i].Network = row
	w.netRev = next
	return nil
}

// --- REQ-34 ---

// backupCharged: control backupCharged (a reserved backup holds its
// MaxBytes, a ready one its archive size).
func backupCharged(b VolumeBackupView) (uint64, bool) {
	switch b.Phase {
	case "Reserved", "Cancelling":
		return b.Source.MaxBytes, true
	case "Ready", "Deleting":
		if r := b.Source.Receipt; r != nil {
			return r.Bytes, true
		}
		return b.Bytes, true
	}
	return 0, false
}

// restoreCharged: a restore holds MaxBytes of staging until cancelled.
func restoreCharged(r VolumeRestoreView) bool { return r.Phase != "Cancelled" }

// backupUsage: what the limit row (tenant "" = the whole server) is charged.
func (w *world) backupUsage(tenant, node string) BackupUsage {
	var u BackupUsage
	for _, b := range w.backups {
		if bytes, ok := backupCharged(b); ok && b.Node == node && (tenant == "" || b.Tenant == tenant) {
			u.Count++
			u.Bytes += bytes
		}
	}
	for _, r := range w.restores {
		if restoreCharged(r) && r.Node == node && (tenant == "" || r.Tenant == tenant) {
			u.StagingCount++
			u.StagingBytes += r.MaxBytes
		}
	}
	return u
}

func (c *fakeConn) volumeBackupLimits(ctx context.Context, tenant, node string) (VolumeBackupLimits, error) {
	const m = "volume-backup-limits"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return VolumeBackupLimits{}, err
	}
	defer c.unlock()
	w := c.f.w
	admin := w.admin(c.session.User)
	var out VolumeBackupLimits
	for _, l := range w.backupLimits {
		if node != "" && l.Node != node || l.Tenant != "" && l.Tenant != tenant {
			continue
		}
		row := BackupLimitRow{Limit: l, Used: w.backupUsage(l.Tenant, l.Node)}
		if l.Original != nil {
			o := *l.Original
			row.Limit.Original = &o
		}
		if l.Tenant == "" && !admin {
			row = BackupLimitRow{Limit: VolumeBackupLimit{Node: l.Node}, Hidden: true}
		}
		out.Rows = append(out.Rows, row)
	}
	slices.SortFunc(out.Rows, func(a, b BackupLimitRow) int {
		return strings.Compare(a.Limit.Node+"/"+a.Limit.Tenant, b.Limit.Node+"/"+b.Limit.Tenant)
	})
	return out, nil
}
