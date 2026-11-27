// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

const ResourcesKey = "control/resources"

type Resources struct {
	Revision uint64
	Networks tenancy.Networks
	Quotas   tenancy.Quotas
}
type resourceRecord struct {
	Schema           uint8
	Cluster          [32]byte
	Revision         uint64
	Networks, Quotas json.RawMessage
}
type NetworkSelection struct{ Tenant, ID string }
type ReservationSelection struct{ Tenant, Key string }

func (p Policy) Resources(s state.State) (Resources, error) {
	raw, revision, err := readCheckpoint(s, ResourcesKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return Resources{}, err
	}
	if raw == nil {
		n, _ := tenancy.New(p.Cluster)
		q, _ := tenancy.NewQuotas(p.Cluster)
		if members, err := p.Members(s); err == nil {
			n = n.WithServers(members.ServerAddresses())
			q = q.WithServerDefaults(serverOwners(members, n, q))
		}
		return Resources{Networks: n, Quotas: q}, nil
	}
	var record resourceRecord
	if canonical(raw, &record) != nil || record.Schema != 1 || record.Cluster != p.Cluster || record.Revision != revision || revision == 0 {
		return Resources{}, ErrCatalog
	}
	n, err := tenancy.Decode(record.Networks)
	if err != nil {
		return Resources{}, err
	}
	q, err := tenancy.DecodeQuotas(record.Quotas)
	if err != nil || n.Cluster() != p.Cluster || q.Cluster() != p.Cluster || n.Revision() > revision || q.Revision() > revision {
		return Resources{}, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil {
		return Resources{}, err
	}
	// A server no administrator gave a node-wide limit uses everything it
	// has (Jay 2026-11-27): its default limit follows from the membership,
	// so nothing is written for it.
	q = q.WithServerDefaults(serverOwners(members, n, q))
	if q.ValidateNetworks(n) != nil {
		return Resources{}, ErrCatalog
	}
	// Every TUN member's tunnel address is its server's fixed address.
	n = n.WithServers(members.ServerAddresses())
	for _, alias := range q.OwnerRotations() {
		rotation, found := members.IdentityRotation(alias.Node, alias.Operation)
		if !found || rotation.Proof == nil || rotation.Phase != "Activated" && rotation.Phase != "Installed" || alias.Index != rotation.ActivatedIndex || alias.Old != rotation.Proof.Old || alias.New != rotation.Proof.New {
			return Resources{}, ErrCatalog
		}
		raw, _ := json.Marshal(rotation.Proof)
		if sha256.Sum256(raw) != alias.Proof {
			return Resources{}, ErrCatalog
		}
	}
	c, err := p.Catalog(s)
	if err != nil {
		return Resources{}, err
	}
	for _, limit := range q.Limits() {
		if limit.Tenant != "" {
			if _, ok := c.Tenant(limit.Tenant); !ok {
				return Resources{}, ErrCatalog
			}
		}
	}
	for _, reservation := range q.Reservations() {
		// Builds derive their sole reservation from the accepted live job.
		// A base checkpoint entry would be a second authority for that slot.
		if strings.HasPrefix(reservation.Key, "workload/imagebuild/") || strings.HasPrefix(reservation.Key, "workload/imagebuild-cache-prune/") {
			return Resources{}, ErrCatalog
		}
		tenant, ok := c.Tenant(reservation.Tenant)
		if !ok || tenant.Phase == access.TenantDeleted {
			return Resources{}, ErrCatalog
		}
	}
	// The network catalog has a complete view; do not use a user's filtered
	// listing to validate ownership against the shared tenant catalog.
	if err := n.ValidateTenants(c); err != nil {
		return Resources{}, ErrCatalog
	}
	return Resources{Revision: revision, Networks: n, Quotas: q}, nil
}
func (p Policy) resourceCheckpoint(s state.State, r Resources) (map[string][]byte, state.Code) {
	if r.Revision == ^uint64(0) || r.Quotas.ValidateNetworks(r.Networks) != nil {
		return nil, state.Invalid
	}
	n, err := r.Networks.Encode()
	if err != nil {
		return nil, state.Invalid
	}
	q, err := r.Quotas.Encode()
	if err != nil {
		return nil, state.Invalid
	}
	// One report can move the networks more than once (use, then create);
	// on a cluster whose first resource write it is, the record must still
	// be at least as new as what it holds.
	r.Revision = max(r.Revision, r.Networks.Revision(), r.Quotas.Revision()) + 1
	raw, err := json.Marshal(resourceRecord{Schema: 1, Cluster: p.Cluster, Revision: r.Revision, Networks: n, Quotas: q})
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, ResourcesKey, p.Cluster, p.TrustRoot, r.Revision, raw)
}

// serverOwners are the servers that have a default node-wide limit while
// none is set: the full members with their current keys, and any server that
// still holds a network or reservation after it left the cluster (removed,
// force-removed), with the key that row was made with. Without the latter a
// removed server's leftover rows would have no limit and no resources read
// would succeed. A server outside the cluster is admitted no new work
// anyway (workNodeOwner).
func serverOwners(d membership.Directory, n tenancy.Networks, q tenancy.Quotas) map[string][32]byte {
	out := map[string][32]byte{}
	for _, e := range d.Entries {
		if !membership.FullMember(e) {
			continue
		}
		if key, err := identity.ParseKey(e.CurrentPeer().Key); err == nil {
			out[e.Peer.ID] = key
		}
	}
	held := func(node string, owner [32]byte) {
		if _, known := out[node]; !known && owner != ([32]byte{}) {
			out[node] = owner
		}
	}
	for _, v := range n.AllNetworks() {
		held(v.Node, v.Owner)
	}
	for _, v := range q.Reservations() {
		held(v.Node, v.Owner)
	}
	return out
}

func (p Policy) nodeOwner(s state.State, id string) ([32]byte, error) {
	directory, err := p.Members(s)
	if err != nil {
		return [32]byte{}, err
	}
	entry, ok := directory.Entry(id)
	if !ok || !membership.FullMember(entry) {
		return [32]byte{}, access.ErrDenied
	}
	return identity.ParseKey(entry.CurrentPeer().Key)
}

// Work ownership is a current admission check. nodeOwner remains an immutable
// identity lookup for original cleanup and history after policy is withdrawn.
func (p Policy) workNodeOwner(s state.State, id string) ([32]byte, error) {
	owner, err := p.nodeOwner(s, id)
	if err != nil {
		return owner, err
	}
	directory, err := p.Members(s)
	if err != nil || !directory.WorkKey(owner) {
		return owner, access.ErrDenied
	}
	return owner, nil
}
func (p Policy) reduceResources(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind != state.Module || cmd.Key != ResourcesKey || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeChange(s, c, op) != nil {
		return nil, state.Forbidden
	}
	r, err := p.Resources(s)
	if err != nil {
		return nil, state.Invalid
	}
	original := r.Networks
	change := op.Change
	var native map[string][]byte
	switch change.Action {
	case "propose-route", "approve-route", "withdraw-route":
		r.Networks, native, err = p.changeRoute(s, c, r, op)
	case "create-virtual-bridge", "approve-virtual-bridge", "close-virtual-bridge":
		r.Networks, err = p.changeBridge(c, r, op)
	case "configure-network-dns":
		native, err = p.configureManagedDNS(s, op)
	case "plan-network-change":
		r.Networks, err = p.planNetworkChange(s, c, r, op)
	case "fence-network-change":
		r.Networks, native, err = p.fenceNetworkChange(s, c, r, op)
	case "commit-network-change":
		r.Networks, native, err = p.commitNetworkChange(s, c, r, op)
	case "reconfigure-tun-network":
		r.Networks, native, err = p.reconfigureNetwork(s, c, r, op)
	case "cancel-network-change":
		var selection NetworkChangeCancel
		if canonical(change.Payload, &selection) != nil {
			return nil, state.Invalid
		}
		r.Networks, err = r.Networks.CancelChange(c, change.Principal, selection.Tenant, selection.ID, selection.Generation, change.Expected, selection.Candidate)
	case "create-tun-network":
		var definition tenancy.TUNDefinition
		if canonical(change.Payload, &definition) != nil {
			return nil, state.Invalid
		}
		if definition.GatewayMode == "" {
			definition.GatewayMode = network.ManagedGatewayMode
		}
		for i := range definition.Members {
			member := &definition.Members[i]
			owner, e := p.workNodeOwner(s, member.Node)
			if e != nil || member.Owner != ([32]byte{}) && member.Owner != owner {
				return nil, state.Forbidden
			}
			member.Owner = owner
		}
		r.Networks, err = r.Networks.CreateTUN(c, r.Quotas, change.Principal, change.Expected, definition)
		if err == nil {
			native, err = newManagedNetworkSources(s, r.Networks, definition.Tenant, definition.Name)
		}
	case "leave-tun-network":
		r.Networks, native, err = p.leaveNetwork(s, c, r, op)
	case "set-network-toggle":
		var v NetworkToggleSet
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		r.Networks, err = r.Networks.SetToggle(c, change.Principal, change.Expected, v.Tenant, v.Name, v.Toggle, v.On)
	case "join-tun-network":
		var join NetworkJoin
		if canonical(change.Payload, &join) != nil {
			return nil, state.Invalid
		}
		owner, e := p.workNodeOwner(s, join.Member.Node)
		if e != nil || join.Member.Owner != ([32]byte{}) && join.Member.Owner != owner {
			return nil, state.Forbidden
		}
		join.Member.Owner = owner
		r.Networks, err = r.Networks.JoinTUN(c, r.Quotas, change.Principal, change.Expected, join.Tenant, join.Name, join.Member)
		if err == nil {
			native, err = joinManagedNetworkSources(s, r.Networks, join.Tenant, join.Name, join.Member.Node)
		}
	case "set-node-quota":
		var limit tenancy.NodeLimit
		if canonical(change.Payload, &limit) != nil {
			return nil, state.Invalid
		}
		owner, e := p.nodeOwner(s, limit.Node)
		if e != nil || limit.Owner != ([32]byte{}) && limit.Owner != owner {
			return nil, state.Forbidden
		}
		limit.Owner = owner
		r.Quotas, err = r.Quotas.Set(c, change.Principal, change.Expected, limit, r.Networks)
	case "reserve-task":
		var reservation tenancy.Reservation
		if canonical(change.Payload, &reservation) != nil || !strings.HasPrefix(reservation.Key, "workload/task/") {
			return nil, state.Invalid
		}
		owner, e := p.workNodeOwner(s, reservation.Node)
		if e != nil || reservation.Owner != ([32]byte{}) && reservation.Owner != owner {
			return nil, state.Forbidden
		}
		reservation.Owner = owner
		r.Quotas, err = r.Quotas.Reserve(c, change.Principal, change.Expected, reservation)
	case "drain-reservation":
		var selection ReservationSelection
		if canonical(change.Payload, &selection) != nil {
			return nil, state.Invalid
		}
		original, ok := r.Quotas.Reservation(selection.Key)
		if !ok || original.Tenant != selection.Tenant {
			return nil, state.Forbidden
		}
		r.Quotas, err = r.Quotas.Drain(c, change.Principal, selection.Key, change.Expected)
	case "release-reservation":
		var proof tenancy.ReservationClosure
		if canonical(change.Payload, &proof) != nil {
			return nil, state.Invalid
		}
		old, ok := r.Quotas.Reservation(proof.Key)
		if !ok || old.Revision != change.Expected {
			return nil, state.ConditionFailed
		}
		r.Quotas, err = r.Quotas.Release(c, change.Principal, proof)
	case "drain-network":
		var selection NetworkSelection
		if canonical(change.Payload, &selection) != nil {
			return nil, state.Invalid
		}
		r.Networks, err = r.Networks.Drain(c, change.Principal, selection.Tenant, selection.ID, change.Expected)
		if err == nil {
			native, err = drainManagedNetworkSources(s, r.Networks, selection.Tenant, selection.ID, cmd)
		}
	default:
		return nil, state.Invalid
	}
	if errors.Is(err, access.ErrDenied) {
		return nil, state.Forbidden
	}
	if code, ok := bridgeRefusalCode(err); ok {
		return nil, code
	}
	if err != nil && systemRangeRefusal(original, change) {
		return nil, state.NetworkSystemRange
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes, code := p.resourceCheckpoint(s, r)
	if code != state.Applied {
		return nil, code
	}
	for key, raw := range native {
		writes[key] = raw
	}
	return writes, code
}

func (p Policy) authorizeResource(s state.State, c access.Catalog, op UserOperation) error {
	action, tenant, node, cleanup := access.Deploy, "", "", false
	switch op.Change.Action {
	case "reconfigure-tun-network":
		var v NetworkReconfigure
		if canonical(op.Change.Payload, &v) != nil || len(v.Members) == 0 || len(v.Members) > 32 || v.Target.Members == nil || len(v.Target.Members) > 32 {
			return access.ErrInvalid
		}
		for _, version := range v.Members {
			if version.Tenant != v.Target.Tenant {
				return access.ErrInvalid
			}
		}
		tenant, action, cleanup = v.Target.Tenant, access.ManageNetwork, len(v.Target.Members) == 0
	case "plan-network-change":
		var v NetworkChangePlan
		if canonical(op.Change.Payload, &v) != nil || v.Target.Tenant != v.Tenant || v.Target.ID != v.ID {
			return access.ErrInvalid
		}
		tenant, node, action = v.Tenant, v.Target.Node, access.ManageNetwork
	case "propose-route", "approve-route", "withdraw-route":
		return p.authorizeRouteChange(s, c, op)
	case "create-virtual-bridge", "approve-virtual-bridge", "close-virtual-bridge":
		return p.authorizeBridgeChange(c, op)
	case "cancel-network-change":
		var v NetworkChangeCancel
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, action, cleanup = v.Tenant, access.ManageNetwork, true
	case "fence-network-change":
		var v NetworkChangeFence
		if canonical(op.Change.Payload, &v) != nil || v.Closed.Tenant != v.Tenant || v.Closed.Network != v.ID {
			return access.ErrInvalid
		}
		tenant, action, cleanup = v.Tenant, access.ManageNetwork, true
	case "commit-network-change":
		var v NetworkChangeCommit
		if canonical(op.Change.Payload, &v) != nil || len(v.Members) == 0 || len(v.Members) > 32 {
			return access.ErrInvalid
		}
		for _, member := range v.Members {
			if member.Tenant != v.Tenant {
				return access.ErrInvalid
			}
		}
		tenant, action = v.Tenant, access.ManageNetwork
	case "configure-network-dns":
		var v services.ManagedDNSDefinition
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, action, cleanup = v.Tenant, access.ManageServices, !v.Policy.Enabled
	case "create-tun-network":
		var v tenancy.TUNDefinition
		if canonical(op.Change.Payload, &v) != nil || len(v.Members) == 0 || len(v.Members) > 32 {
			return access.ErrInvalid
		}
		for _, member := range v.Members {
			if err := c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, access.ManageNetwork, member.Node); err != nil {
				return err
			}
		}
		return nil
	case "join-tun-network":
		var v NetworkJoin
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, access.ManageNetwork, v.Member.Node)
	case "set-network-toggle":
		var v NetworkToggleSet
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, action = v.Tenant, access.ManageNetwork
	case "set-node-quota":
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	case "reserve-task":
		var v tenancy.Reservation
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, node = v.Tenant, v.Node
	case "drain-reservation":
		var v ReservationSelection
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, cleanup = v.Tenant, true
	case "release-reservation":
		var v tenancy.ReservationClosure
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		parts := strings.Split(v.Key, "/")
		if len(parts) != 5 || parts[0] != "workload" || parts[1] != "task" {
			return access.ErrInvalid
		}
		tenant, cleanup = parts[2], true
	case "drain-network":
		var v NetworkSelection
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, action, cleanup = v.Tenant, access.ManageNetwork, true
	case "leave-tun-network":
		var v tenancy.NetworkClosure
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		tenant, action, cleanup = v.Tenant, access.ManageNetwork, true
	default:
		return access.ErrInvalid
	}
	if cleanup {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, tenant, action)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, tenant, action, node)
}

// resourcesBook is the ResourcesKey book (books.go).
var resourcesBook = Book{Key: ResourcesKey, Reduce: byKind(map[state.CommandKind]reducer{state.ModuleReport: reduceResourceReport, state.Module: Policy.reduceResources})}

// reduceResourceReport takes a node's resource report: a closed Bridge or a
// system network report. A report from anyone else is refused.
func reduceResourceReport(p Policy, s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if !nodeActor(cmd) {
		return refuseKind(p, s, cmd)
	}
	if bridgeClosedValue(cmd.Value) {
		return p.reduceBridgeClosedReport(s, cmd)
	}
	return p.reduceSystemNetworkReport(s, cmd)
}
