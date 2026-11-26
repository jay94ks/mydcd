// SPDX-License-Identifier: Apache-2.0

// Package deployment contains the reusable application planning/consumption
// core. Its candidates have no I/O: the FSM must publish all grants and pins
// atomically with the original operation result, before any provider read or
// native effect. CLI and embedded controllers consume this same core.
package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

var ErrInputs = errors.New("application input scope, approval, ownership or projection conflict")

const maxInputs = 256

// Source is qualified even when two realms use the same stable object ID.
// Realm empty means the explicitly shared cluster tree, not an implicit default.
type Source struct{ Realm, Object string }
type Projection struct {
	Key, Target    string
	UID, GID, Mode uint32
	Kind           string `json:",omitempty"` // empty/file is a mounted file; env targets an environment name
}
type VolumeNeed struct {
	Key      string
	Writable bool
}
type Needs struct {
	ResourceKeys    []lifecycle.IdentityTransition `json:",omitempty"`
	Instance        *TaskInstance                  `json:",omitempty"` // frozen consumer identity; Use.Service remains logical
	Consumer        string
	Generation      uint64
	Use             secrets.Use // Sources must be empty: the single ordered list is below.
	Sources         []Source
	RegistrySources []Source `json:",omitempty"` // approved for image auth, never app file/env merge
	Volumes         []VolumeNeed
	Files           []Projection
	FixedVolumes    map[string]VolumeReference `json:",omitempty"`
	Lifecycle       *checker.Selection         `json:",omitempty"`
}
type VolumePin struct {
	Key      string
	Scope    volumes.Scope
	Consumer volumes.Consumer
}
type bindingRecord struct {
	Schema         uint8
	Cluster        [32]byte
	Needs          Needs
	Grants         []secrets.Grant
	RegistryGrants []secrets.Grant `json:",omitempty"`
	Pins           []VolumePin
}

// Binding is public metadata only. Read access comes from current registries;
// neither a copied binding nor its digest is a bearer capability.
type Binding struct{ d bindingRecord }
type Reservation struct {
	Inventory Bindings
	Approvals secrets.Approvals
	Volumes   map[string]volumes.State
	Bindings  []Binding
}

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}
func ownNeeds(n Needs) Needs {
	n.ResourceKeys = lifecycle.OwnIdentityTransitions(n.ResourceKeys)
	if n.Instance != nil {
		instance := *n.Instance
		n.Instance = &instance
	}
	if n.Lifecycle != nil {
		v := n.Lifecycle.Clone()
		n.Lifecycle = &v
	}
	n.Use.Sources = slices.Clone(n.Use.Sources)
	n.Sources = slices.Clone(n.Sources)
	n.RegistrySources = slices.Clone(n.RegistrySources)
	n.Volumes = slices.Clone(n.Volumes)
	n.Files = slices.Clone(n.Files)
	if n.FixedVolumes != nil {
		refs := make(map[string]VolumeReference, len(n.FixedVolumes))
		for key, ref := range n.FixedVolumes {
			refs[key] = ref
		}
		n.FixedVolumes = refs
	}
	return n
}
func ownGrant(g secrets.Grant) secrets.Grant {
	g.Use.Sources = slices.Clone(g.Use.Sources)
	g.Pins = slices.Clone(g.Pins)
	return g
}
func ownBinding(d bindingRecord) bindingRecord {
	d.Needs = ownNeeds(d.Needs)
	d.Grants = slices.Clone(d.Grants)
	for i := range d.Grants {
		d.Grants[i] = ownGrant(d.Grants[i])
	}
	d.RegistryGrants = slices.Clone(d.RegistryGrants)
	for i := range d.RegistryGrants {
		d.RegistryGrants[i] = ownGrant(d.RegistryGrants[i])
	}
	d.Pins = slices.Clone(d.Pins)
	return d
}
func (b Binding) Needs() Needs { return ownNeeds(b.d.Needs) }
func (b Binding) Grants() []secrets.Grant {
	d := ownBinding(b.d)
	return append(d.Grants, d.RegistryGrants...)
}
func (b Binding) ProjectionGrants() []secrets.Grant { return ownBinding(b.d).Grants }
func (b Binding) RegistryGrants() []secrets.Grant   { return ownBinding(b.d).RegistryGrants }
func (b Binding) Pins() []VolumePin                 { return slices.Clone(b.d.Pins) }
func (b Binding) Digest() [32]byte                  { raw, _ := json.Marshal(b.d); return sha256.Sum256(raw) }
func VolumeKey(s volumes.Scope) string              { return s.Key() }
func useEqual(a, b secrets.Use) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}
func sameBase(a, b secrets.Use) bool {
	a.Service = ""
	a.Node = ""
	a.NodeKey = [32]byte{}
	a.Sources = nil
	b.Service = ""
	b.Node = ""
	b.NodeKey = [32]byte{}
	b.Sources = nil
	return useEqual(a, b)
}

func validKey(k string) bool {
	if len(k) < 1 || len(k) > 128 || k == "." || k == ".." {
		return false
	}
	for _, b := range []byte(k) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '.' || b == '-') {
			return false
		}
	}
	return true
}
func validProjection(p Projection) bool {
	if !validKey(p.Key) || p.Mode != 0400 && p.Mode != 0440 {
		return false
	}
	if p.Kind == "env" {
		return workload.SecretEnvironmentName(p.Target) && p.UID == 0 && p.GID == 0 && p.Mode == 0400
	}
	return (p.Kind == "" || p.Kind == "file") && workload.SecretFileTarget(p.Target)
}

func validNeeds(n Needs) bool {
	return identifier(n.Consumer) && n.Generation > 0 && validInputMetadata(n)
}
func validInputMetadata(n Needs) bool {
	if n.Lifecycle != nil && n.Lifecycle.Validate() != nil {
		return false
	}
	u := n.Use
	if u.Purpose != "" {
		return false
	} // app bindings cannot borrow source-service approval
	if n.Instance != nil && (n.Instance.Ordinal == 0 || n.Instance.Service != u.Service || n.Instance.Node != u.Node || n.Instance.ResourceID() == "") {
		return false
	}
	if !identifier(u.Tenant) || !identifier(u.User) || !identifier(u.App) || !identifier(u.Deployment) || !identifier(u.Service) || !identifier(u.Node) || u.RequesterKey == ([32]byte{}) || u.NodeKey == ([32]byte{}) || len(u.Sources) != 0 || len(n.Sources) > maxInputs || len(n.Volumes) > maxInputs || len(n.Files) > maxInputs || len(n.Sources) == 0 && len(n.Files) != 0 {
		return false
	}
	if len(n.RegistrySources) > 2 || len(n.Sources)+len(n.RegistrySources) > maxInputs {
		return false
	}
	for i, source := range n.RegistrySources {
		if slices.Contains(n.RegistrySources[:i], source) {
			return false
		}
	}
	for _, s := range n.ApprovalSources() {
		if !identifier(s.Object) || s.Realm != "" && s.Realm != u.Tenant {
			return false
		}
	}
	for i, v := range n.Volumes {
		parts := strings.Split(v.Key, "/")
		ref, fixed := n.FixedVolumes[v.Key]
		if len(parts) != 3 || parts[0] != u.Tenant || !identifier(parts[2]) || !fixed && parts[1] != u.App || fixed && (parts[1] != "@tenant" || !ref.Valid() || ref.Scope.Key() != v.Key || ref.Scope.Tenant != u.Tenant || ref.Owner.Node != u.Node || !n.resourceIdentity(ref.Scope.Cluster, ref.Owner.Key)) {
			return false
		}
		for _, old := range n.Volumes[:i] {
			if old.Key == v.Key {
				return false
			}
		}
	}
	for key := range n.FixedVolumes {
		if !slices.ContainsFunc(n.Volumes, func(v VolumeNeed) bool { return v.Key == key }) {
			return false
		}
	}
	for i, p := range n.Files {
		if !validProjection(p) {
			return false
		}
		for _, q := range n.Files[:i] {
			if (p.Kind == "env") == (q.Kind == "env") && workload.OverlappingMounts(p.Target, q.Target) {
				return false
			}
		}
	}
	return true
}
func realmUses(n Needs) map[string]secrets.Use {
	out := map[string]secrets.Use{}
	for _, s := range n.Sources {
		u, ok := out[s.Realm]
		if !ok {
			u = n.Use
		}
		u.Sources = append(u.Sources, s.Object)
		out[s.Realm] = u
	}
	return out
}

func approvalRealmUses(n Needs) map[string]secrets.Use {
	n.Sources = n.ApprovalSources()
	n.RegistrySources = nil
	return realmUses(n)
}

func registryInputNeeds(n Needs) Needs {
	hash := sha256.Sum256(append([]byte("mydc-registry-input-consumer-1\x00"), []byte(n.Consumer)...))
	n.Consumer = "registry-" + hex.EncodeToString(hash[:24])
	n.Sources = slices.Clone(n.RegistrySources)
	n.RegistrySources = nil
	n.Files = nil
	n.Volumes = nil
	n.FixedVolumes = nil
	n.Lifecycle = nil
	return n
}

func (n Needs) HasSources() bool { return len(n.Sources) > 0 || len(n.RegistrySources) > 0 }

// ApprovalSources preserves the app override order. Auxiliary registry reads
// share original approval/use lifetime but never change app key precedence.
func (n Needs) ApprovalSources() []Source {
	out := slices.Clone(n.Sources)
	return append(out, n.RegistrySources...)
}
func realms(n Needs) []string {
	m := realmUses(n)
	out := make([]string, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}
func copyVolumes(v map[string]volumes.State) map[string]volumes.State {
	out := make(map[string]volumes.State, len(v))
	for k, s := range v {
		out[k] = s
	}
	return out
}

// Required plans one password prompt per required realm/group across all
// service/node consumers. Source ordering and approval set ordering are distinct.
func Required(cluster [32]byte, c access.Catalog, trees map[string]secrets.Tree, needs []Needs) ([]secrets.Target, error) {
	if cluster == ([32]byte{}) || len(needs) < 1 || len(needs) > maxInputs {
		return nil, ErrInputs
	}
	uses := map[string][]secrets.Use{}
	consumers := map[string]bool{}
	nodeKeys := map[string][32]byte{}
	for _, n := range needs {
		if !validNeeds(n) || !sameBase(needs[0].Use, n.Use) || consumers[n.Consumer] || c.Authorize(n.Use.User, n.Use.Tenant, access.Deploy, n.Use.Node) != nil {
			return nil, ErrInputs
		}
		if k, ok := nodeKeys[n.Use.Node]; ok && k != n.Use.NodeKey {
			return nil, ErrInputs
		}
		consumers[n.Consumer] = true
		nodeKeys[n.Use.Node] = n.Use.NodeKey
		for realm, u := range approvalRealmUses(n) {
			uses[realm] = append(uses[realm], u)
		}
	}
	var result []secrets.Target
	for realm, us := range uses {
		t, ok := trees[realm]
		if !ok || t.Cluster() != cluster || t.Realm() != realm {
			return nil, ErrInputs
		}
		plan, e := t.Plan(c, us)
		if e != nil {
			return nil, e
		}
		result = append(result, plan.Required...)
	}
	slices.SortFunc(result, func(a, b secrets.Target) int {
		if a.Realm != b.Realm {
			return strings.Compare(a.Realm, b.Realm)
		}
		return strings.Compare(a.Group, b.Group)
	})
	return result, nil
}

// Missing filters the combined prompt set through current stored approvals.
// A partially approved apply asks only for the remaining groups on resume.
func Missing(cluster [32]byte, c access.Catalog, trees map[string]secrets.Tree, a secrets.Approvals, needs []Needs, now int64) ([]secrets.Target, error) {
	if now < 0 || a.Cluster() != cluster {
		return nil, ErrInputs
	}
	if _, e := Required(cluster, c, trees, needs); e != nil {
		return nil, e
	}
	uses := map[string][]secrets.Use{}
	for _, n := range needs {
		for realm, u := range approvalRealmUses(n) {
			uses[realm] = append(uses[realm], u)
		}
	}
	var result []secrets.Target
	for realm, us := range uses {
		t := trees[realm]
		p, e := t.Plan(c, us)
		if e != nil {
			return nil, e
		}
		result = append(result, a.Missing(c, t, p, now)...)
	}
	slices.SortFunc(result, func(a, b secrets.Target) int {
		if a.Realm != b.Realm {
			return strings.Compare(a.Realm, b.Realm)
		}
		return strings.Compare(a.Group, b.Group)
	})
	return result, nil
}

// Reserve returns the entire candidate or no candidate. Publishing only some
// returned registries would violate its transaction contract. It reads no values
// and never releases an original unknown effect to make a reservation succeed.
func reserve(cluster [32]byte, c access.Catalog, trees map[string]secrets.Tree, a secrets.Approvals, v map[string]volumes.State, needs []Needs, now int64) (Reservation, error) {
	if a.Cluster() != cluster || now < 0 {
		return Reservation{}, ErrInputs
	}
	if _, e := Required(cluster, c, trees, needs); e != nil {
		return Reservation{}, e
	}
	q := Reservation{Approvals: a, Volumes: copyVolumes(v)}
	for _, n := range needs {
		b := Binding{bindingRecord{Schema: 1, Cluster: cluster, Needs: ownNeeds(n)}}
		for purpose, group := range []Needs{n, registryInputNeeds(n)} {
			uses := realmUses(group)
			for _, realm := range realms(group) {
				var grant secrets.Grant
				var err error
				q.Approvals, grant, err = q.Approvals.Acquire(c, trees[realm], uses[realm], group.Consumer, group.Generation, q.Approvals.Revision(), now)
				if err != nil {
					return Reservation{}, err
				}
				if purpose == 0 {
					b.d.Grants = append(b.d.Grants, grant)
				} else {
					b.d.RegistryGrants = append(b.d.RegistryGrants, grant)
				}
			}
		}
		for _, wanted := range n.Volumes {
			s, ok := q.Volumes[wanted.Key]
			if !ok || VolumeKey(s.Scope()) != wanted.Key || s.Scope().Cluster != cluster {
				return Reservation{}, ErrInputs
			}
			if ref, fixed := n.FixedVolumes[wanted.Key]; fixed && !ref.MatchesState(s) || !fixed && s.Fixed() {
				return Reservation{}, ErrInputs
			}
			owner, _ := s.Owner()
			if owner.Node != n.Use.Node || !n.resourceIdentity(cluster, owner.Key) {
				return Reservation{}, ErrInputs
			}
			next, pin, e := s.Acquire(c, n.Use.User, s.Revision(), n.Consumer, n.Generation, wanted.Writable)
			if e != nil || next.CheckActivation(pin) != nil {
				return Reservation{}, ErrInputs
			}
			q.Volumes[wanted.Key] = next
			b.d.Pins = append(b.d.Pins, VolumePin{wanted.Key, s.Scope(), pin})
		}
		q.Bindings = append(q.Bindings, b)
	}
	return q, nil
}

func validBinding(b Binding) bool {
	d := b.d
	if d.Schema != 1 || d.Cluster == ([32]byte{}) || !d.Needs.resourceIdentity(d.Cluster, d.Needs.Use.NodeKey) || !validNeeds(d.Needs) || len(d.Grants) != len(realms(d.Needs)) || len(d.RegistryGrants) != len(realms(registryInputNeeds(d.Needs))) || len(d.Pins) != len(d.Needs.Volumes) {
		return false
	}
	us := realmUses(d.Needs)
	for i, r := range realms(d.Needs) {
		g := d.Grants[i]
		if g.Realm != r || g.Consumer != d.Needs.Consumer || g.Generation != d.Needs.Generation || !useEqual(g.Use, us[r]) || g.Selection == ([32]byte{}) || g.Lifetime.Token == 0 || g.Lifetime.Generation != 1 || len(g.Pins) > 4096 {
			return false
		}
	}
	rn := registryInputNeeds(d.Needs)
	ru := realmUses(rn)
	for i, realm := range realms(rn) {
		g := d.RegistryGrants[i]
		if g.Realm != realm || g.Consumer != rn.Consumer || g.Generation != rn.Generation || !useEqual(g.Use, ru[realm]) || g.Selection == ([32]byte{}) || g.Lifetime.Token == 0 || g.Lifetime.Generation != 1 || len(g.Pins) > 4096 {
			return false
		}
	}
	for i, p := range d.Pins {
		if p.Key != d.Needs.Volumes[i].Key || VolumeKey(p.Scope) != p.Key || p.Scope.Cluster != d.Cluster || p.Scope.Generation == 0 || p.Consumer.ID != d.Needs.Consumer || p.Consumer.Generation != d.Needs.Generation || p.Consumer.Writable != d.Needs.Volumes[i].Writable || p.Consumer.Owner.Node != d.Needs.Use.Node || !d.Needs.resourceIdentity(d.Cluster, p.Consumer.Owner.Key) || p.Consumer.Lease.Token == 0 || p.Consumer.Lease.Generation != p.Scope.Generation || p.Consumer.OwnerRevision == 0 {
			return false
		}
		if ref, fixed := d.Needs.FixedVolumes[p.Key]; fixed && (ref.Scope != p.Scope || ref.Owner != p.Consumer.Owner || ref.Scope.Cluster != d.Cluster) || !fixed && p.Scope.TenantManaged() {
			return false
		}
	}
	return true
}
func (b Binding) Encode() ([]byte, error) {
	if !validBinding(b) {
		return nil, ErrInputs
	}
	raw, e := json.Marshal(b.d)
	if len(raw) > 1<<20 {
		return nil, ErrInputs
	}
	return raw, e
}
func DecodeBinding(raw []byte) (Binding, error) {
	if len(raw) > 1<<20 {
		return Binding{}, ErrInputs
	}
	var d bindingRecord
	if json.Unmarshal(raw, &d) != nil {
		return Binding{}, ErrInputs
	}
	b := Binding{d}
	if !validBinding(b) {
		return Binding{}, ErrInputs
	}
	canonical, _ := json.Marshal(d)
	if !bytes.Equal(raw, canonical) {
		return Binding{}, ErrInputs
	}
	return b, nil
}

// Check revalidates all sources/approval policies and exact original volume
// pins before a NEW read/materialization. Already running users settle through
// original receipts even after policy revoke or loss of node admission.
func (b Binding) Check(inventory Bindings, c access.Catalog, trees map[string]secrets.Tree, a secrets.Approvals, v map[string]volumes.State, now int64) error {
	if !inventory.Owns(b) || !validBinding(b) || now < 0 || a.Cluster() != b.d.Cluster || c.Authorize(b.d.Needs.Use.User, b.d.Needs.Use.Tenant, access.Deploy, b.d.Needs.Use.Node) != nil {
		return ErrInputs
	}
	for _, g := range b.d.Grants {
		t, ok := trees[g.Realm]
		if !ok || t.Cluster() != b.d.Cluster || t.Realm() != g.Realm {
			return ErrInputs
		}
		if _, e := a.ReadSet(c, t, g, now); e != nil {
			return e
		}
	}
	for _, pin := range b.d.Pins {
		s, ok := v[pin.Key]
		if !ok || s.Scope() != pin.Scope || s.CheckActivation(pin.Consumer) != nil {
			return ErrInputs
		}
		if ref, fixed := b.d.Needs.FixedVolumes[pin.Key]; fixed && !ref.MatchesState(s) || !fixed && s.Fixed() {
			return ErrInputs
		}
	}
	return nil
}

type Closure struct {
	Secrets []secrets.UseGone
	Volumes []volumes.Gone
}

// Release settles the original generation as one metadata candidate. Every
// proof must come from the original owner, and every original pin must match.
// It does not delete provider values or retained native volume data.
func (b Binding) release(a secrets.Approvals, v map[string]volumes.State, proof Closure) (Reservation, error) {
	if !validBinding(b) || a.Cluster() != b.d.Cluster || len(proof.Secrets) != len(b.Grants()) || len(proof.Volumes) != len(b.d.Pins) {
		return Reservation{}, ErrInputs
	}
	q := Reservation{Approvals: a, Volumes: copyVolumes(v)}
	for i, g := range b.Grants() {
		p := proof.Secrets[i]
		u := g.Use
		if p.Cluster != b.d.Cluster || p.Realm != g.Realm || p.Tenant != u.Tenant || p.App != u.App || p.Deployment != u.Deployment || p.Consumer != g.Consumer || p.Generation != g.Generation || p.NodeKey != u.NodeKey || p.Selection != g.Selection || p.Lifetime != g.Lifetime {
			return Reservation{}, ErrInputs
		}
		var e error
		q.Approvals, e = q.Approvals.ReleaseUse(p)
		if e != nil {
			return Reservation{}, e
		}
	}
	for i, pin := range b.d.Pins {
		p := proof.Volumes[i]
		s, ok := q.Volumes[pin.Key]
		if !ok || s.Scope() != pin.Scope || p.Scope != pin.Scope || p.Consumer != pin.Consumer {
			return Reservation{}, ErrInputs
		}
		next, e := s.Release(p)
		if e != nil {
			return Reservation{}, e
		}
		q.Volumes[pin.Key] = next
	}
	return q, nil
}
