// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
)

type Definition struct {
	Node       string
	Key        [32]byte
	ID, Path   string
	Tenants    []string
	MaxVolumes int
}

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
	if !identifier(d.Node) || d.Key == ([32]byte{}) || !identifier(d.ID) || !cleanPath(d.Path) || d.MaxVolumes < 1 || d.MaxVolumes > maxVolumes || len(d.Tenants) > maxRoots {
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
	if expected != 0 || !validDefinition(d) || !policyTenants(users, d.Tenants) || c.next == ^uint64(0) || len(c.roots) >= maxRoots || len(c.floors) >= maxRoots && c.floors[rootKey(d.Node, d.ID)] == 0 {
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

func (c Catalog) SetPolicy(users access.Catalog, actor, node, id string, expected uint64, tenants []string, max int, registered int) (Catalog, error) {
	if !users.SystemAllowed(actor) {
		return c, access.ErrDenied
	}
	r, ok := c.roots[rootKey(node, id)]
	d := r.Definition
	d.Tenants = slices.Clone(tenants)
	d.MaxVolumes = max
	if !ok || r.Revision != expected || r.Draining || !validDefinition(d) || !policyTenants(users, tenants) || registered < 0 || registered > max {
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
	if !ok || r.Generation != generation || r.Draining || r.Closed != nil || r.Attestation == nil || !slices.Contains(r.Definition.Tenants, tenant) {
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
