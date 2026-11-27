// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
)

// Definition is a storage root's registration and policy. AllTenants lets
// every tenant use the root (Tenants is then empty). CapacityBytes bounds the
// sum of the reservations of the fixed volumes registered on the root; zero is
// no limit. It is admission accounting, not a filesystem quota.
type Definition struct {
	Node          string
	Key           [32]byte
	ID, Path      string
	Tenants       []string
	AllTenants    bool   `json:",omitempty"`
	CapacityBytes uint64 `json:",omitempty"`
}

// Allows reports whether the root's policy lets tenant use it.
func (d Definition) Allows(tenant string) bool {
	return d.AllTenants || slices.Contains(d.Tenants, tenant)
}

// DefaultRootID names the root each node registers for itself once, on its
// first run in a cluster (RegisterDefault). An operator may change or remove
// it like any other root; a removed default root is never registered again.
const DefaultRootID = "default"

// RootPinCapacity bounds the native pins (volumes, build artifacts) one root
// holds at a time. It is not a user policy.
const RootPinCapacity = maxRoots

// MaxCapacityBytes bounds a root's capacity so reservation sums cannot overflow.
const MaxCapacityBytes = 1 << 60

type Root struct {
	Definition           Definition
	Generation, Revision uint64
	Draining             bool
	Attestation          *RootFact   `json:",omitempty"`
	Closed               *RootClosed `json:",omitempty"`
}

func (r Root) Reference(cluster [32]byte) Reference {
	return Reference{cluster, r.Definition.Node, r.Definition.Key, r.Definition.ID, r.Generation, r.Definition.Path}
}
func ownRoot(r Root) Root {
	r.Definition.Tenants = slices.Clone(r.Definition.Tenants)
	if r.Attestation != nil {
		f := ownFact(*r.Attestation)
		r.Attestation = &f
	}
	if r.Closed != nil {
		f := *r.Closed
		f.Signature = slices.Clone(f.Signature)
		r.Closed = &f
	}
	return r
}

// Catalog is immutable. Counts supplied to SetPolicy/Remove are derived by the
// control reducer from the SAME full committed Volume snapshot, never a user
// count or a partial/empty remote observation. Actual pins also gate RootClosed.
type Catalog struct {
	cluster        [32]byte
	revision, next uint64
	roots          map[string]Root
	floors         map[string]uint64
}

func New(cluster [32]byte) (Catalog, error) {
	if cluster == ([32]byte{}) {
		return Catalog{}, ErrStorage
	}
	return Catalog{cluster: cluster, roots: map[string]Root{}, floors: map[string]uint64{}}, nil
}
func rootKey(node, id string) string { return node + "/" + id }
func (c Catalog) Cluster() [32]byte  { return c.cluster }
func (c Catalog) Revision() uint64   { return c.revision }
func (c Catalog) Root(node, id string) (Root, bool) {
	r, ok := c.roots[rootKey(node, id)]
	return ownRoot(r), ok
}
func (c Catalog) Roots() []Root {
	keys := make([]string, 0, len(c.roots))
	for k := range c.roots {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	rows := make([]Root, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, ownRoot(c.roots[k]))
	}
	return rows
}
func (c Catalog) clone() (Catalog, error) {
	if c.cluster == ([32]byte{}) || c.roots == nil || c.floors == nil || c.revision == ^uint64(0) {
		return c, ErrStorage
	}
	n := c
	n.revision++
	n.roots = map[string]Root{}
	n.floors = map[string]uint64{}
	for k, r := range c.roots {
		n.roots[k] = ownRoot(r)
	}
	for k, g := range c.floors {
		n.floors[k] = g
	}
	return n, nil
}

func validDefinition(d Definition) bool {
	if !identifier(d.Node) || d.Key == ([32]byte{}) || !identifier(d.ID) || !cleanPath(d.Path) || d.CapacityBytes > MaxCapacityBytes || len(d.Tenants) > maxRoots || d.AllTenants && len(d.Tenants) != 0 {
		return false
	}
	for i, t := range d.Tenants {
		if !identifier(t) || i > 0 && d.Tenants[i-1] >= t {
			return false
		}
	}
	return true
}
func policyTenants(c access.Catalog, tenants []string) bool {
	for _, id := range tenants {
		t, ok := c.Tenant(id)
		if !ok || !t.Enabled || t.Phase != access.TenantActive {
			return false
		}
	}
	return true
}
func (c Catalog) Add(users access.Catalog, actor string, expected uint64, d Definition) (Catalog, error) {
	if !users.SystemAllowed(actor) {
		return c, access.ErrDenied
	}
	if expected != 0 || !policyTenants(users, d.Tenants) {
		return c, ErrStorage
	}
	return c.add(d)
}

// Registered reports whether node ever registered a root named id in this
// cluster, including one an operator has since removed.
func (c Catalog) Registered(node, id string) bool {
	_, ok := c.floors[rootKey(node, id)]
	return ok
}

// DefaultDefinition is the root a node registers for itself: every tenant may
// use it and it has no capacity limit.
func DefaultDefinition(node string, key [32]byte, path string) Definition {
	return Definition{Node: node, Key: key, ID: DefaultRootID, Path: path, AllTenants: true}
}

// RegisterDefault adds the node's own default root. The caller has already
// proven the reporter is the node's current owner. It refuses once the node
// has ever registered a root by that name, so an operator's removal sticks
// across restarts and rejoins.
func (c Catalog) RegisterDefault(d Definition) (Catalog, error) {
	if d.ID != DefaultRootID || !d.AllTenants || len(d.Tenants) != 0 || d.CapacityBytes != 0 || c.Registered(d.Node, d.ID) {
		return c, ErrStorage
	}
	return c.add(d)
}

func (c Catalog) add(d Definition) (Catalog, error) {
	if !validDefinition(d) || c.next == ^uint64(0) || len(c.roots) >= maxRoots || len(c.floors) >= maxRoots && c.floors[rootKey(d.Node, d.ID)] == 0 {
		return c, ErrStorage
	}
	if _, ok := c.roots[rootKey(d.Node, d.ID)]; ok {
		return c, ErrStorage
	}
	for _, r := range c.roots {
		if r.Definition.Node == d.Node && (within(r.Definition.Path, d.Path) || within(d.Path, r.Definition.Path)) {
			return c, ErrStorage
		}
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	n.next++
	r := Root{Definition: d, Generation: n.next, Revision: n.revision}
	r = ownRoot(r)
	n.roots[rootKey(d.Node, d.ID)] = r
	n.floors[rootKey(d.Node, d.ID)] = r.Generation
	return n, nil
}

// Policy is a delta to a root's policy. AllTenants, when set, switches between
// "every tenant" and an explicit list; switching to the list starts it from
// Add. Capacity, when set, replaces the capacity limit (0 = no limit).
type Policy struct {
	Add, Remove []string
	AllTenants  *bool
	Capacity    *uint64
}

func (p Policy) Empty() bool {
	return len(p.Add) == 0 && len(p.Remove) == 0 && p.AllTenants == nil && p.Capacity == nil
}

// ChangePolicy applies a policy delta. Expected is the root's revision. Adding
// a tenant that is already allowed, removing one that is not, or editing the
// list while every tenant is allowed is a conflict. reserved is the sum of the
// reservations already held on the root; a limit below it is refused.
func (c Catalog) ChangePolicy(users access.Catalog, actor, node, id string, expected uint64, q Policy, reserved uint64) (Catalog, error) {
	if !users.SystemAllowed(actor) {
		return c, access.ErrDenied
	}
	r, ok := c.roots[rootKey(node, id)]
	if !ok || r.Revision != expected || r.Draining || q.Empty() {
		return c, ErrStorage
	}
	d := r.Definition
	all := d.AllTenants
	if q.AllTenants != nil {
		if *q.AllTenants == all {
			return c, ErrStorage
		}
		all = *q.AllTenants
	}
	tenants := slices.Clone(d.Tenants)
	switch {
	case all && (len(q.Add) != 0 || len(q.Remove) != 0):
		return c, ErrStorage
	case all:
		tenants = nil
	case d.AllTenants: // switching to an explicit list
		if len(q.Remove) != 0 {
			return c, ErrStorage
		}
		tenants = nil
	}
	if !all {
		for _, t := range q.Remove {
			i := slices.Index(tenants, t)
			if i < 0 {
				return c, ErrStorage
			}
			tenants = slices.Delete(tenants, i, i+1)
		}
		for _, t := range q.Add {
			if slices.Contains(tenants, t) || slices.Contains(d.Tenants, t) {
				return c, ErrStorage
			}
			tenants = append(tenants, t)
		}
		slices.Sort(tenants)
	}
	d.AllTenants, d.Tenants = all, tenants
	if q.Capacity != nil {
		d.CapacityBytes = *q.Capacity
	}
	if !validDefinition(d) || !policyTenants(users, q.Add) || d.CapacityBytes != 0 && reserved > d.CapacityBytes {
		return c, ErrStorage
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	r.Definition = d
	r.Revision = n.revision
	n.roots[rootKey(node, id)] = ownRoot(r)
	return n, nil
}

func (c Catalog) Observe(f RootFact, reporter [32]byte) (Catalog, error) {
	r, ok := c.roots[rootKey(f.Root.Node, f.Root.ID)]
	if !ok || f.Verify() != nil || reporter != r.Definition.Key || f.Root != r.Reference(c.cluster) || r.Draining {
		return c, ErrStorage
	}
	if r.Attestation != nil {
		if !r.Attestation.Directory.SameData(f.Directory) {
			return c, ErrStorage
		}
		return c, nil // do not rewrite the original native identity or TTL facts
	}
	for _, other := range c.roots {
		if other.Definition.Node != r.Definition.Node || other.Definition.ID == r.Definition.ID || other.Attestation == nil {
			continue
		}
		old := other.Attestation.Directory
		if old.Filesystem == f.Directory.Filesystem && old.UUID == f.Directory.UUID {
			if within(old.FilesystemPath, f.Directory.FilesystemPath) || within(f.Directory.FilesystemPath, old.FilesystemPath) {
				return c, ErrStorage
			}
			if old.Boot == f.Directory.Boot && (old.DeviceMajor != f.Directory.DeviceMajor || old.DeviceMinor != f.Directory.DeviceMinor) {
				return c, ErrStorage
			}
		}
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	f = ownFact(f)
	r.Attestation = &f
	r.Revision = n.revision
	n.roots[rootKey(f.Root.Node, f.Root.ID)] = r
	return n, nil
}

func (c Catalog) Drain(users access.Catalog, actor, node, id string, expected uint64) (Catalog, error) {
	if !users.SystemAllowed(actor) {
		return c, access.ErrDenied
	}
	r, ok := c.roots[rootKey(node, id)]
	if !ok || r.Revision != expected || r.Draining {
		return c, ErrStorage
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	r.Draining = true
	r.Revision = n.revision
	n.roots[rootKey(node, id)] = r
	return n, nil
}
func (c Catalog) ObserveClosed(f RootClosed, reporter [32]byte) (Catalog, error) {
	r, ok := c.roots[rootKey(f.Root.Node, f.Root.ID)]
	if !ok || !r.Draining || f.Verify() != nil || reporter != r.Definition.Key || f.Root != r.Reference(c.cluster) {
		return c, ErrStorage
	}
	if r.Closed != nil {
		return c, nil
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	f.Signature = slices.Clone(f.Signature)
	r.Closed = &f
	r.Revision = n.revision
	n.roots[rootKey(f.Root.Node, f.Root.ID)] = r
	return n, nil
}
func (c Catalog) Remove(users access.Catalog, actor, node, id string, expected uint64, registered int) (Catalog, error) {
	if !users.SystemAllowed(actor) {
		return c, access.ErrDenied
	}
	r, ok := c.roots[rootKey(node, id)]
	if !ok || r.Revision != expected || !r.Draining || r.Closed == nil || registered != 0 {
		return c, ErrStorage
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	delete(n.roots, rootKey(node, id))
	return n, nil
}

func (c Catalog) CanUse(users access.Catalog, actor, tenant, node, id string, generation uint64) (Root, error) {
	return c.canUse(users, actor, tenant, node, id, generation, access.ManageVolumes)
}

// CanBuild uses the same registered-root/ACL/attestation boundary for image
// contexts without granting the caller Volume management rights.
func (c Catalog) CanBuild(users access.Catalog, actor, tenant, node, id string, generation uint64) (Root, error) {
	return c.canUse(users, actor, tenant, node, id, generation, access.ManageRegistry)
}
func (c Catalog) canUse(users access.Catalog, actor, tenant, node, id string, generation uint64, action access.Action) (Root, error) {
	r, ok := c.roots[rootKey(node, id)]
	if !ok || r.Generation != generation || r.Draining || r.Closed != nil || r.Attestation == nil || !r.Definition.Allows(tenant) {
		return Root{}, ErrStorage
	}
	if users.Authorize(actor, tenant, action, node) != nil {
		return Root{}, access.ErrDenied
	}
	return ownRoot(r), nil
}

type rootFloor struct {
	Key        string
	Generation uint64
}
type checkpoint struct {
	Schema         uint8
	Cluster        [32]byte
	Revision, Next uint64
	Roots          []Root
	Floors         []rootFloor
}

func (c Catalog) Encode() ([]byte, error) {
	if c.cluster == ([32]byte{}) || c.roots == nil || c.floors == nil || c.next > c.revision || c.next == 0 && c.revision != 0 || len(c.roots) > maxRoots || len(c.floors) > maxRoots {
		return nil, ErrStorage
	}
	d := checkpoint{Schema: 1, Cluster: c.cluster, Revision: c.revision, Next: c.next, Roots: c.Roots()}
	keys := make([]string, 0, len(c.floors))
	for k := range c.floors {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	seen := map[uint64]bool{}
	var highest uint64
	for _, k := range keys {
		g := c.floors[k]
		node, id, ok := strings.Cut(k, "/")
		if !ok || !identifier(node) || !identifier(id) || g == 0 || g > c.next || seen[g] {
			return nil, ErrStorage
		}
		seen[g] = true
		highest = max(highest, g)
		d.Floors = append(d.Floors, rootFloor{k, g})
	}
	if highest != c.next {
		return nil, ErrStorage
	}
	for i, r := range d.Roots {
		if !validDefinition(r.Definition) || r.Generation == 0 || r.Generation > c.next || r.Revision < r.Generation || r.Revision > c.revision || c.floors[rootKey(r.Definition.Node, r.Definition.ID)] != r.Generation {
			return nil, ErrStorage
		}
		if r.Attestation != nil && (r.Attestation.Verify() != nil || r.Attestation.Root != r.Reference(c.cluster)) {
			return nil, ErrStorage
		}
		if r.Closed != nil && (!r.Draining || r.Closed.Verify() != nil || r.Closed.Root != r.Reference(c.cluster)) {
			return nil, ErrStorage
		}
		for _, other := range d.Roots[:i] {
			if other.Definition.Node != r.Definition.Node {
				continue
			}
			if within(other.Definition.Path, r.Definition.Path) || within(r.Definition.Path, other.Definition.Path) {
				return nil, ErrStorage
			}
			if other.Attestation != nil && r.Attestation != nil {
				a, b := other.Attestation.Directory, r.Attestation.Directory
				if a.Filesystem == b.Filesystem && a.UUID == b.UUID && (within(a.FilesystemPath, b.FilesystemPath) || within(b.FilesystemPath, a.FilesystemPath) || a.Boot == b.Boot && (a.DeviceMajor != b.DeviceMajor || a.DeviceMinor != b.DeviceMinor)) {
					return nil, ErrStorage
				}
			}
		}
	}
	return json.Marshal(d)
}
func Decode(raw []byte) (Catalog, error) {
	var d checkpoint
	if len(raw) > 8<<20 || json.Unmarshal(raw, &d) != nil || d.Schema != 1 {
		return Catalog{}, ErrStorage
	}
	c, err := New(d.Cluster)
	if err != nil {
		return c, err
	}
	c.revision, c.next = d.Revision, d.Next
	for _, r := range d.Roots {
		k := rootKey(r.Definition.Node, r.Definition.ID)
		if _, dup := c.roots[k]; dup {
			return Catalog{}, ErrStorage
		}
		c.roots[k] = ownRoot(r)
	}
	for _, f := range d.Floors {
		if _, dup := c.floors[f.Key]; dup {
			return Catalog{}, ErrStorage
		}
		c.floors[f.Key] = f.Generation
	}
	canonical, err := c.Encode()
	if err != nil || !bytes.Equal(raw, canonical) {
		return Catalog{}, ErrStorage
	}
	return c, nil
}
