// SPDX-License-Identifier: Apache-2.0

// Package secrets contains secret metadata, selection and approval policy. It
// never stores passwords, verifiers, secret values or value hashes in Tree.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
)

var ErrPolicy = errors.New("secret policy or revision conflict")

const maxObjects = 4096
const maxDepth = 32

type Kind string

const (
	Group  Kind = "group"
	Secret Kind = "secret"
)

type Status string

const (
	Active           Status = "active"
	PasswordPending  Status = "password-pending"
	Revoking         Status = "revoking"
	Retired          Status = "retired"
	ReferencePending Status = "reference-pending"
)

// Empty allow sets inherit unrestricted selection within the tenant boundary.
// Every ancestor rule must pass; any deny wins. Global tree use additionally
// requires an explicit tenant grant on its root, including for system admins.
type ACL struct {
	Users, Services, DenyUsers, DenyServices []string
	TenantGrants                             []string
}
type Reference struct {
	Profile, Object string
	Revision        uint64
	Keys            []string
}
type Object struct {
	ID, Parent                           string
	Kind                                 Kind
	Generation, Revision, PolicyRevision uint64
	Status                               Status
	ACL                                  ACL
	Entries                              []string
	Protected                            bool
	AuthPolicy                           uint64
	VerifierRef, PasswordChange          string
	PendingWrite                         string
	MaxApprovalAge                       int64
	Reference                            Reference
	VerifierBinding                      *VerifierBinding `json:",omitempty"`
}
type Tree struct {
	cluster      [32]byte
	tenant, root string
	revision     uint64
	objects      map[string]Object
	writeEpoch   uint64
	profiles     map[string]WriteProfile
	writes       map[string]WriteRecord
}

func (t Tree) Cluster() [32]byte { return t.cluster }
func (t Tree) Realm() string     { return t.tenant }

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func cleanText(s string) bool {
	return len(s) > 0 && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n")
}
func validKey(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return s != "." && s != ".."
}
func sortedIDs(v []string) ([]string, error) {
	v = slices.Clone(v)
	slices.Sort(v)
	if len(v) > 256 {
		return nil, ErrPolicy
	}
	for i, s := range v {
		if !identifier(s) || i > 0 && s == v[i-1] {
			return nil, ErrPolicy
		}
	}
	return v, nil
}
func ownACL(a ACL) ACL {
	a.Users = slices.Clone(a.Users)
	a.Services = slices.Clone(a.Services)
	a.DenyUsers = slices.Clone(a.DenyUsers)
	a.DenyServices = slices.Clone(a.DenyServices)
	a.TenantGrants = slices.Clone(a.TenantGrants)
	return a
}
func canonicalACL(a ACL) (ACL, error) {
	fields := []*[]string{&a.Users, &a.Services, &a.DenyUsers, &a.DenyServices, &a.TenantGrants}
	for _, f := range fields {
		v, err := sortedIDs(*f)
		if err != nil {
			return ACL{}, err
		}
		*f = v
	}
	return a, nil
}
func ownObject(o Object) Object {
	o.ACL = ownACL(o.ACL)
	o.Entries = slices.Clone(o.Entries)
	o.Reference.Keys = slices.Clone(o.Reference.Keys)
	if o.VerifierBinding != nil {
		v := *o.VerifierBinding
		v.Reference.Keys = slices.Clone(v.Reference.Keys)
		o.VerifierBinding = &v
	}
	return o
}
func canonicalReference(r Reference) (Reference, error) {
	if r.Revision == 0 {
		return r, ErrPolicy
	}
	return referenceShape(r)
}
func referenceShape(r Reference) (Reference, error) {
	if !identifier(r.Profile) || !cleanText(r.Object) || len(r.Keys) == 0 || len(r.Keys) > 256 {
		return r, ErrPolicy
	}
	r.Keys = slices.Clone(r.Keys)
	slices.Sort(r.Keys)
	for i, k := range r.Keys {
		if !validKey(k) || i > 0 && k == r.Keys[i-1] {
			return r, ErrPolicy
		}
	}
	return r, nil
}
func NewTree(cluster [32]byte, tenant, root string) (Tree, error) {
	if cluster == ([32]byte{}) || tenant != "" && !identifier(tenant) || !identifier(root) {
		return Tree{}, ErrPolicy
	}
	o := Object{ID: root, Kind: Group, Generation: 1, Revision: 1, PolicyRevision: 1, Status: Active}
	return Tree{cluster: cluster, tenant: tenant, root: root, revision: 1, objects: map[string]Object{root: o}, writeEpoch: 1, profiles: map[string]WriteProfile{}, writes: map[string]WriteRecord{}}, nil
}
func (t Tree) Revision() uint64                { return t.revision }
func (t Tree) Object(id string) (Object, bool) { o, ok := t.objects[id]; return ownObject(o), ok }
func (t Tree) managed(c access.Catalog, actor string) bool {
	if t.tenant == "" {
		return c.SystemAllowed(actor)
	}
	return c.Authorize(actor, t.tenant, access.ManageSecrets, "") == nil
}
func (t Tree) clone() (Tree, error) {
	if t.cluster == ([32]byte{}) || t.objects == nil || t.revision == ^uint64(0) {
		return t, ErrPolicy
	}
	n := t
	n.revision++
	n.objects = map[string]Object{}
	for id, o := range t.objects {
		n.objects[id] = ownObject(o)
	}
	n.profiles = map[string]WriteProfile{}
	for id, p := range t.profiles {
		n.profiles[id] = p
	}
	n.writes = map[string]WriteRecord{}
	for id, w := range t.writes {
		n.writes[id] = ownWrite(w)
	}
	return n, nil
}
func (t Tree) path(id string) ([]Object, error) {
	var path []Object
	seen := map[string]bool{}
	for id != "" {
		o, ok := t.objects[id]
		if !ok || seen[id] || len(path) >= maxDepth {
			return nil, ErrPolicy
		}
		seen[id] = true
		path = append(path, ownObject(o))
		id = o.Parent
	}
	if len(path) == 0 || path[len(path)-1].ID != t.root {
		return nil, ErrPolicy
	}
	slices.Reverse(path)
	return path, nil
}
func (t Tree) Create(c access.Catalog, actor string, expected uint64, o Object) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	if expected != t.revision {
		return t, access.ErrConflict
	}
	if !identifier(o.ID) || !identifier(o.Parent) || o.Kind != Group && o.Kind != Secret || o.Generation != 0 || o.Revision != 0 || o.PolicyRevision != 0 || o.AuthPolicy != 0 || o.Status != "" || len(o.Entries) != 0 || o.Protected || o.VerifierRef != "" || o.VerifierBinding != nil || o.PasswordChange != "" || o.PendingWrite != "" || o.MaxApprovalAge != 0 || len(t.objects) >= maxObjects {
		return t, ErrPolicy
	}
	if _, ok := t.objects[o.ID]; ok {
		return t, access.ErrConflict
	}
	parent, ok := t.objects[o.Parent]
	if !ok || parent.Kind != Group || parent.Status != Active {
		return t, ErrPolicy
	}
	var err error
	o.ACL, err = canonicalACL(o.ACL)
	if err != nil || len(o.ACL.TenantGrants) != 0 {
		return t, ErrPolicy
	}
	if o.Kind == Secret {
		o.Reference, err = referenceShape(o.Reference)
		if err != nil {
			return t, err
		}
	} else if o.Reference.Profile != "" || o.Reference.Object != "" || o.Reference.Revision != 0 || len(o.Reference.Keys) != 0 {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.Generation = n.revision
	o.Revision = n.revision
	o.PolicyRevision = n.revision
	o.Status = Active
	if o.Kind == Secret && o.Reference.Revision == 0 {
		o.Status = ReferencePending
	}
	n.objects[o.ID] = ownObject(o)
	parent = ownObject(parent)
	parent.Entries = append(parent.Entries, o.ID)
	parent.Revision = n.revision
	n.objects[parent.ID] = parent
	if _, err = n.path(o.ID); err != nil {
		return t, err
	}
	return n, nil
}
func (t Tree) SetACL(c access.Catalog, actor, id string, expected uint64, a ACL) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	a, err := canonicalACL(a)
	if err != nil || len(a.TenantGrants) > 0 && (t.tenant != "" || id != t.root) || o.Status != Active {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.ACL = a
	o.Revision = n.revision
	o.PolicyRevision = n.revision
	n.objects[id] = ownObject(o)
	return n, nil
}
func (t Tree) Reorder(c access.Catalog, actor, id string, expected uint64, entries []string) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	if o.Kind != Group || o.Status != Active || len(entries) != len(o.Entries) {
		return t, ErrPolicy
	}
	seen := map[string]bool{}
	for _, id := range entries {
		if seen[id] || !slices.Contains(o.Entries, id) {
			return t, ErrPolicy
		}
		seen[id] = true
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.Entries = slices.Clone(entries)
	o.Revision = n.revision
	n.objects[id] = ownObject(o)
	return n, nil
}
func (t Tree) Move(c access.Catalog, actor, id, parent string, expected uint64) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	p, ok := t.objects[parent]
	if !ok || p.Kind != Group || p.Status != Active || o.Status != Active || id == t.root || o.Parent == parent {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	old := ownObject(n.objects[o.Parent])
	i := slices.Index(old.Entries, id)
	if i < 0 {
		return t, ErrPolicy
	}
	old.Entries = append(old.Entries[:i], old.Entries[i+1:]...)
	old.Revision = n.revision
	n.objects[old.ID] = old
	p = ownObject(n.objects[parent])
	p.Entries = append(p.Entries, id)
	p.Revision = n.revision
	n.objects[parent] = p
	o.Parent = parent
	o.Revision = n.revision
	o.PolicyRevision = n.revision
	n.objects[id] = ownObject(o)
	for id := range n.objects {
		if _, err = n.path(id); err != nil {
			return t, err
		}
	}
	return n, nil
}

// PublishReference is only a metadata transition. The runtime writer must first
// settle the ORIGINAL provider operation using A2/read-back and retain its
// receipt; this method neither writes provider data nor declares an unknown
// write not-applied. c/expected are checked again after that external effect.
func (t Tree) PublishReference(c access.Catalog, actor, id string, expected uint64, r Reference) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	if o.Kind != Secret || o.Status != Active && o.Status != ReferencePending || o.PendingWrite != "" {
		return t, ErrPolicy
	}
	r, err := canonicalReference(r)
	if err != nil {
		return t, err
	}
	if r.Profile != o.Reference.Profile || r.Object != o.Reference.Object || r.Revision <= o.Reference.Revision {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.Reference = r
	o.Status = Active
	o.Revision = n.revision
	n.objects[id] = ownObject(o)
	return n, nil
}
func (t Tree) BeginPasswordChange(c access.Catalog, actor, id, change string, expected uint64) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	if o.Kind != Group || o.Status != Active || o.PendingWrite != "" || !identifier(change) {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.Status = PasswordPending
	o.PasswordChange = change
	o.Revision = n.revision
	o.PolicyRevision = n.revision
	o.AuthPolicy = n.revision
	n.objects[id] = ownObject(o)
	return n, nil
}
func (t Tree) SetApprovalAge(c access.Catalog, actor, id string, expected uint64, seconds int64) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	if o.Kind != Group || o.Status != Active || seconds < 0 {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.MaxApprovalAge = seconds
	o.Revision = n.revision
	o.PolicyRevision = n.revision
	n.objects[id] = ownObject(o)
	return n, nil
}

// ActivatePassword runs only after the original verifier write is positively
// settled in the protected backend. ref is an opaque record ID, never a KDF
// verifier/hash or password. The actual adapter must preserve pending writes.
func (t Tree) ActivatePassword(c access.Catalog, actor, id, change, ref string, protected bool, expected uint64) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	if o.Kind != Group || o.Status != PasswordPending || o.PendingWrite != "" || change != o.PasswordChange || protected && !identifier(ref) || !protected && ref != "" {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.Status = Active
	o.Protected = protected
	o.VerifierRef = ref
	o.VerifierBinding = nil
	o.PasswordChange = ""
	o.AuthPolicy = n.revision
	o.PolicyRevision = n.revision
	o.Revision = n.revision
	n.objects[id] = ownObject(o)
	return n, nil
}
func (t Tree) Revoke(c access.Catalog, actor, id string, expected uint64) (Tree, error) {
	allowed := c.AuthorizeCleanup(actor, t.tenant, access.ManageSecrets) == nil
	if t.tenant == "" {
		allowed = c.SystemAllowed(actor)
	}
	if !allowed {
		return t, access.ErrDenied
	}
	o, ok := t.objects[id]
	if !ok || o.Revision != expected {
		return t, access.ErrConflict
	}
	if o.Status == Retired || id == t.root {
		return t, ErrPolicy
	}
	if o.Status == Revoking {
		return t, nil
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	o.Status = Revoking
	o.Revision = n.revision
	o.PolicyRevision = n.revision
	n.objects[id] = ownObject(o)
	return n, nil
}

type treeRecord struct {
	Schema       uint8
	Cluster      [32]byte
	Tenant, Root string
	Revision     uint64
	Objects      []Object
	WriteEpoch   uint64
	Profiles     []WriteProfile
	Writes       []WriteRecord
}

func (t Tree) Encode() ([]byte, error) {
	if t.cluster == ([32]byte{}) || t.objects == nil {
		return nil, ErrPolicy
	}
	r := treeRecord{Schema: 1, Cluster: t.cluster, Tenant: t.tenant, Root: t.root, Revision: t.revision, WriteEpoch: t.writeEpoch}
	for _, o := range t.objects {
		r.Objects = append(r.Objects, ownObject(o))
	}
	slices.SortFunc(r.Objects, func(a, b Object) int { return strings.Compare(a.ID, b.ID) })
	for _, p := range t.profiles {
		r.Profiles = append(r.Profiles, p)
	}
	slices.SortFunc(r.Profiles, func(a, b WriteProfile) int { return strings.Compare(a.ID, b.ID) })
	for _, w := range t.writes {
		r.Writes = append(r.Writes, ownWrite(w))
	}
	slices.SortFunc(r.Writes, func(a, b WriteRecord) int { return strings.Compare(a.Request.ID, b.Request.ID) })
	return json.Marshal(r)
}
func DecodeTree(b []byte) (Tree, error) {
	var r treeRecord
	if json.Unmarshal(b, &r) != nil || r.Schema != 1 || r.Revision == 0 || len(r.Objects) > maxObjects || r.WriteEpoch == 0 || len(r.Profiles) > 256 || len(r.Writes) > maxObjects {
		return Tree{}, ErrPolicy
	}
	t, err := NewTree(r.Cluster, r.Tenant, r.Root)
	if err != nil {
		return Tree{}, err
	}
	t.revision = r.Revision
	t.writeEpoch = r.WriteEpoch
	t.objects = map[string]Object{}
	for _, o := range r.Objects {
		if _, dup := t.objects[o.ID]; dup || !identifier(o.ID) || o.Kind != Group && o.Kind != Secret || o.Generation == 0 || o.Revision < o.Generation || o.Revision > r.Revision || o.PolicyRevision < o.Generation || o.PolicyRevision > o.Revision || o.AuthPolicy > o.Revision || o.MaxApprovalAge < 0 {
			return Tree{}, ErrPolicy
		}
		if o.Status != Active && o.Status != PasswordPending && o.Status != Revoking && o.Status != Retired && o.Status != ReferencePending {
			return Tree{}, ErrPolicy
		}
		if o.VerifierBinding != nil && (o.Kind != Group || !o.Protected || !validVerifierBinding(r.Tenant, o)) {
			return Tree{}, ErrPolicy
		}
		if o.Status == Retired && (len(o.Entries) > 0 || o.PendingWrite != "" || o.PasswordChange != "") {
			return Tree{}, ErrPolicy
		}
		a, err := canonicalACL(o.ACL)
		ab, _ := json.Marshal(a)
		ob, _ := json.Marshal(o.ACL)
		if err != nil || !bytes.Equal(ab, ob) || len(a.TenantGrants) > 0 && (r.Tenant != "" || o.ID != r.Root) {
			return Tree{}, ErrPolicy
		}
		if o.Kind == Secret {
			v, err := referenceShape(o.Reference)
			vb, _ := json.Marshal(v)
			ob, _ := json.Marshal(o.Reference)
			if err != nil || !bytes.Equal(vb, ob) || len(o.Entries) > 0 || o.Protected || o.AuthPolicy != 0 || o.VerifierRef != "" || o.PasswordChange != "" || o.MaxApprovalAge != 0 || o.Status == PasswordPending || o.Status == Active && v.Revision == 0 || o.Status == ReferencePending && v.Revision != 0 {
				return Tree{}, ErrPolicy
			}
		} else {
			if o.Reference.Profile != "" || o.Reference.Object != "" || o.Reference.Revision != 0 || len(o.Reference.Keys) > 0 || o.Protected && (!identifier(o.VerifierRef) || o.AuthPolicy == 0) || !o.Protected && o.VerifierRef != "" || o.Status == PasswordPending && (!identifier(o.PasswordChange) || o.AuthPolicy == 0) || o.Status != PasswordPending && o.Status != Revoking && o.PasswordChange != "" || o.PasswordChange != "" && !identifier(o.PasswordChange) || o.Status == ReferencePending {
				return Tree{}, ErrPolicy
			}
		}
		t.objects[o.ID] = ownObject(o)
	}
	root, ok := t.objects[r.Root]
	if !ok || root.Parent != "" || root.Kind != Group || root.Status != Active && root.Status != PasswordPending {
		return Tree{}, ErrPolicy
	}
	for id, o := range t.objects {
		if _, err = t.path(id); err != nil {
			return Tree{}, err
		}
		seen := map[string]bool{}
		for _, child := range o.Entries {
			v, ok := t.objects[child]
			if !ok || v.Status == Retired || v.Parent != id || seen[child] {
				return Tree{}, ErrPolicy
			}
			seen[child] = true
		}
		if id != r.Root && o.Status != Retired {
			p, ok := t.objects[o.Parent]
			if !ok || p.Kind != Group || !slices.Contains(p.Entries, id) {
				return Tree{}, ErrPolicy
			}
		}
	}
	for _, p := range r.Profiles {
		if _, dup := t.profiles[p.ID]; dup || !validProfile(p) || p.Revision > t.revision {
			return Tree{}, ErrPolicy
		}
		t.profiles[p.ID] = p
	}
	for _, w := range r.Writes {
		if _, dup := t.writes[w.Request.ID]; dup || !t.validWrite(w) {
			return Tree{}, ErrPolicy
		}
		t.writes[w.Request.ID] = ownWrite(w)
	}
	for _, o := range t.objects {
		if o.PendingWrite != "" {
			w, ok := t.writes[o.PendingWrite]
			if !ok || w.Request.Object != o.ID || w.Generation != o.Generation || writeTerminal(w) {
				return Tree{}, ErrPolicy
			}
		}
	}
	canonical, err := t.Encode()
	if err != nil || !bytes.Equal(b, canonical) {
		return Tree{}, ErrPolicy
	}
	return t, nil
}
