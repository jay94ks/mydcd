// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// WriteProfile grants only a designated node's public key the authority to
// report original provider effects and serve exact approved value reads.
// Installation config separately binds the
// profile to real HTTPS/CA/path/credential restrictions. No URL/token is here.
type WriteProfile struct {
	Mode                       string `json:",omitempty"`
	ID, Node                   string
	Key                        [32]byte
	Revision                   uint64
	Enabled, Values, Verifiers bool
}
type WriteKind string

const (
	ValueWrite    WriteKind = "value"
	VerifierWrite WriteKind = "verifier"
)

type WriteRequest struct {
	ID, Object, Profile, ProviderObject string
	Epoch, ExpectedProviderRevision     uint64
	Kind                                WriteKind
	Keys                                []string
	Protected                           bool
}
type WriteRecord struct {
	Request                            WriteRequest
	Actor                              string
	Generation, ExpectedObjectRevision uint64
	Writer                             WriteProfile
	Journal                            reconcile.State
	Observation                        *WriteObservation
	PublishedRevision                  uint64
	Abandoned                          bool
}

func (w WriteRecord) Status() string {
	if !identifier(w.Request.ID) || w.Request.Epoch == 0 || w.Journal.LastID == 0 || reconcile.Validate(w.Journal) != nil {
		return "Invalid"
	}
	if w.Abandoned {
		return "Abandoned"
	}
	if w.PublishedRevision != 0 {
		return "Published"
	}
	if w.Journal.Pending != nil {
		switch w.Journal.Pending.Phase {
		case reconcile.Prepared:
			return "Prepared"
		case reconcile.Dispatched:
			return "Dispatched"
		case reconcile.RecoveryRequired:
			return "Unknown"
		}
	}
	if w.Journal.Applied.Present {
		return "StoredUnreferenced"
	}
	if w.Observation != nil && w.Observation.Outcome == reconcile.EffectNotApplied {
		return "NotApplied"
	}
	return "Invalid"
}

// Observation contains only safe receipts/status, never value/verifier bytes,
// hashes or arbitrary provider error text. Writer signs after original-ID
// readback or authoritative terminal non-execution, not merely a timeout.
type WriteObservation struct {
	Cluster                            [32]byte
	Tenant                             string
	Request                            WriteRequest
	Generation, ExpectedObjectRevision uint64
	Writer                             WriteProfile
	Operation                          uint64
	Observer                           WriteProfile
	Outcome                            reconcile.Outcome
	ProviderRevision                   uint64
	VerifierRef                        string
	// Builtin writes only: the voter that signs this observation, the
	// SHA-256 of the sealed value, and the voters that hold it (sorted).
	Reporter  [32]byte        `json:",omitempty"`
	Digest    [32]byte        `json:",omitempty"`
	Holders   []HolderReceipt `json:",omitempty"`
	Signature []byte
}

func ownRequest(r WriteRequest) WriteRequest { r.Keys = slices.Clone(r.Keys); return r }
func ownWrite(w WriteRecord) WriteRecord {
	w.Request = ownRequest(w.Request)
	if w.Journal.Pending != nil {
		p := *w.Journal.Pending
		w.Journal.Pending = &p
	}
	if w.Observation != nil {
		p := *w.Observation
		p.Request = ownRequest(p.Request)
		p.Signature = slices.Clone(p.Signature)
		p.Holders = slices.Clone(p.Holders)
		w.Observation = &p
	}
	return w
}
func WriteObservationBytes(p WriteObservation) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-secret-write-observation-1\x00"), b...)
}

// validProfile is an installed profile; the builtin one is never stored.
func validProfile(p WriteProfile) bool {
	return p.ID != BuiltinProfile && identifier(p.ID) && identifier(p.Node) && p.Key != ([32]byte{}) && p.Revision > 0 && (p.Values || p.Verifiers) && (p.Mode == "" || p.Mode == "vault" || p.Mode == "local-file" && p.Values && !p.Verifiers)
}
func usableProfile(p WriteProfile) bool { return p.Builtin() || validProfile(p) }

func (t Tree) profile(id string) (WriteProfile, bool) {
	if id == BuiltinProfile {
		return BuiltinWriteProfile(), true
	}
	p, ok := t.profiles[id]
	return p, ok
}
func (t Tree) WriteEpoch() uint64                  { return t.writeEpoch }
func (t Tree) Write(id string) (WriteRecord, bool) { w, ok := t.writes[id]; return ownWrite(w), ok }

// PlanWrite derives the provider target from the current object and validates
// the exact same candidate as PrepareWrite without publishing it or private
// input. A caller cannot redirect a value/verifier to an arbitrary provider key.
func (t Tree) PlanWrite(c access.Catalog, actor, id, object, profile string, kind WriteKind, keys []string) (WriteRequest, error) {
	o, ok := t.Object(object)
	if !ok {
		return WriteRequest{}, ErrPolicy
	}
	r := WriteRequest{ID: id, Object: object, Profile: profile, Epoch: t.writeEpoch, Kind: kind, Keys: slices.Clone(keys)}
	switch kind {
	case ValueWrite:
		if profile != "" && profile != o.Reference.Profile {
			return r, ErrPolicy
		}
		r.Profile, r.ProviderObject, r.ExpectedProviderRevision = o.Reference.Profile, o.Reference.Object, o.Reference.Revision
		if len(r.Keys) == 0 {
			r.Keys = slices.Clone(o.Reference.Keys)
		}
		slices.Sort(r.Keys)
	case VerifierWrite:
		if binding, err := t.Verifier(object); err == nil {
			if profile != "" && profile != binding.Reference.Profile {
				return r, ErrPolicy
			}
			r.Profile, r.ExpectedProviderRevision = binding.Reference.Profile, binding.Reference.Revision
		} else if r.Profile == "" {
			r.Profile = t.DefaultProfile(VerifierWrite)
		}
		r.ProviderObject, r.Protected = verifierObject(t.tenant, object, o.Generation), true
	default:
		return r, ErrPolicy
	}
	_, err := t.PrepareWrite(c, actor, t.Revision(), r)
	return r, err
}
func (t Tree) SetWriteProfile(c access.Catalog, actor string, expected uint64, p WriteProfile) (Tree, error) {
	if !c.SystemAllowed(actor) {
		return t, access.ErrDenied
	}
	if expected != t.revision {
		return t, access.ErrConflict
	}
	if p.Revision != 0 {
		return t, ErrPolicy
	}
	p.Revision = t.revision + 1
	if p.ID == BuiltinProfile || p.Mode == BuiltinProfile || !validProfile(p) {
		return t, ErrPolicy
	}
	if _, ok := t.profiles[p.ID]; !ok && len(t.profiles) >= 256 {
		return t, ErrPolicy
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	p.Revision = n.revision
	n.profiles[p.ID] = p
	return n, nil
}
func writeSpec(cluster [32]byte, tenant string, w WriteRecord) string {
	v := struct {
		Cluster                            [32]byte
		Tenant                             string
		Request                            WriteRequest
		Actor                              string
		Generation, ExpectedObjectRevision uint64
		Writer                             WriteProfile
	}{cluster, tenant, w.Request, w.Actor, w.Generation, w.ExpectedObjectRevision, w.Writer}
	b, _ := json.Marshal(v)
	return string(b)
}
func sameRequest(a, b WriteRequest) bool {
	return a.ID == b.ID && a.Object == b.Object && a.Profile == b.Profile && a.ProviderObject == b.ProviderObject && a.Epoch == b.Epoch && a.ExpectedProviderRevision == b.ExpectedProviderRevision && a.Kind == b.Kind && a.Protected == b.Protected && slices.Equal(a.Keys, b.Keys)
}
func verifierObject(tenant, id string, generation uint64) string {
	if tenant == "" {
		tenant = "_cluster"
	}
	return "groups/" + tenant + "/" + id + "/" + strconv.FormatUint(generation, 10)
}
func writeTerminal(w WriteRecord) bool { return w.PublishedRevision != 0 || w.Abandoned }

// PendingWrites preserves prepared/dispatched/unknown provider work through
// policy withdrawal. A saved value or missing observer alone is not closure.
func (t Tree) PendingWrites(owner [32]byte) uint32 {
	var count uint32
	for _, write := range t.writes {
		if write.Writer.Key == owner && !writeTerminal(write) {
			count++
		}
	}
	return count
}

// PrepareWrite opens exactly one provider operation per object. A verifier
// change and its Pending policy are part of the same candidate. Caller syncs
// the candidate before dispatch, while private input stays out of the record.
func (t Tree) PrepareWrite(c access.Catalog, actor string, expected uint64, r WriteRequest) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	if expected != t.revision {
		return t, access.ErrConflict
	}
	if r.Epoch != t.writeEpoch || !identifier(r.ID) {
		return t, ErrPolicy
	}
	r = ownRequest(r)
	if r.Kind == ValueWrite {
		slices.Sort(r.Keys)
	}
	if old, exists := t.writes[r.ID]; exists {
		if sameRequest(old.Request, r) {
			return t, nil
		}
		return t, access.ErrConflict
	}
	if len(t.writes) >= maxObjects {
		return t, ErrPolicy
	}
	o, ok := t.objects[r.Object]
	if !ok || o.PendingWrite != "" {
		return t, ErrPolicy
	}
	p, ok := t.profile(r.Profile)
	if !ok || !p.Enabled || p.Mode == "local-file" || !cleanText(r.ProviderObject) {
		return t, ErrPolicy
	}
	var n Tree
	var err error
	switch r.Kind {
	case ValueWrite:
		if !p.Values || o.Kind != Secret || o.Status != Active && o.Status != ReferencePending || r.Profile != o.Reference.Profile || r.ProviderObject != o.Reference.Object || r.ExpectedProviderRevision != o.Reference.Revision || r.Protected {
			return t, ErrPolicy
		}
		if _, err = referenceShape(Reference{Profile: r.Profile, Object: r.ProviderObject, Revision: r.ExpectedProviderRevision, Keys: r.Keys}); err != nil {
			return t, err
		}
		n, err = t.clone()
	case VerifierWrite:
		if !p.Verifiers || o.Kind != Group || o.Status != Active || len(r.Keys) != 0 || r.ProviderObject != verifierObject(t.tenant, o.ID, o.Generation) {
			return t, ErrPolicy
		}
		n, err = t.BeginPasswordChange(c, actor, o.ID, r.ID, o.Revision)
	default:
		return t, ErrPolicy
	}
	if err != nil {
		return t, err
	}
	o = n.objects[r.Object]
	w := WriteRecord{Request: r, Actor: actor, Generation: o.Generation, ExpectedObjectRevision: o.Revision, Writer: p}
	w.Journal, err = reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: n.revision, Resource: reconcile.Resource{Generation: o.Generation, Spec: writeSpec(n.cluster, n.tenant, w), Present: true}})
	if err != nil {
		return t, err
	}
	w.Journal, _, err = reconcile.Plan(w.Journal)
	if err != nil {
		return t, err
	}
	o.PendingWrite = r.ID
	n.objects[o.ID] = ownObject(o)
	n.writes[r.ID] = ownWrite(w)
	return n, nil
}
func (t Tree) DispatchWrite(c access.Catalog, actor, id string, epoch, expected uint64) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	if expected != t.revision || epoch != t.writeEpoch {
		return t, access.ErrConflict
	}
	w, ok := t.writes[id]
	if !ok || writeTerminal(w) {
		return t, ErrPolicy
	}
	p, ok := t.profile(w.Request.Profile)
	if !ok || !p.Enabled || p != w.Writer {
		return t, access.ErrDenied
	}
	o := t.objects[w.Request.Object]
	if o.Generation != w.Generation || o.Revision != w.ExpectedObjectRevision || o.Status != Active && o.Status != ReferencePending && o.Status != PasswordPending {
		return t, ErrPolicy
	}
	if w.Journal.Pending == nil {
		return t, ErrPolicy
	}
	journal, err := reconcile.Dispatch(w.Journal, w.Journal.Pending.ID)
	if err != nil {
		return t, err
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	w = ownWrite(w)
	w.Journal = journal
	n.writes[id] = w
	return n, nil
}
func (t Tree) validObservation(w WriteRecord, p WriteObservation) bool {
	if w.Writer.Builtin() {
		if !validBuiltinObservation(w, p) {
			return false
		}
	} else if p.Reporter != ([32]byte{}) || p.Digest != ([32]byte{}) || len(p.Holders) != 0 {
		return false
	}
	key := w.Writer.Key
	if w.Writer.Builtin() {
		key = p.Reporter
	}
	if p.Observer != (WriteProfile{}) {
		if !validProfile(p.Observer) || p.Observer.Mode == "local-file" || !p.Observer.Enabled || p.Observer.ID != w.Request.Profile || p.Observer.Revision > t.revision || p.Outcome == reconcile.EffectNotApplied || w.Request.Kind == ValueWrite && !p.Observer.Values || w.Request.Kind == VerifierWrite && !p.Observer.Verifiers {
			return false
		}
		key = p.Observer.Key
	}
	if p.Cluster != t.cluster || p.Tenant != t.tenant || !sameRequest(p.Request, w.Request) || p.Generation != w.Generation || p.ExpectedObjectRevision != w.ExpectedObjectRevision || p.Writer != w.Writer || p.Operation != w.Journal.LastID || p.Operation == 0 || p.Outcome < reconcile.EffectApplied || p.Outcome > reconcile.EffectUnknown || !ed25519.Verify(ed25519.PublicKey(key[:]), WriteObservationBytes(p), p.Signature) {
		return false
	}
	if p.Outcome != reconcile.EffectApplied {
		return p.ProviderRevision == 0 && p.VerifierRef == ""
	}
	if p.ProviderRevision <= w.Request.ExpectedProviderRevision {
		return false
	}
	if w.Request.Kind == VerifierWrite {
		return w.Request.Protected && identifier(p.VerifierRef) || !w.Request.Protected && p.VerifierRef == ""
	}
	return p.VerifierRef == ""
}
func (t Tree) ObserveWrite(p WriteObservation) (Tree, error) {
	w, ok := t.writes[p.Request.ID]
	if p.Observer != (WriteProfile{}) {
		current, exists := t.profile(p.Observer.ID)
		if !exists || current != p.Observer {
			return t, ErrPolicy
		}
	}
	if !ok || p.Request.Epoch != t.writeEpoch || !t.validObservation(w, p) {
		return t, ErrPolicy
	}
	if w.Observation != nil && bytes.Equal(WriteObservationBytes(*w.Observation), WriteObservationBytes(p)) {
		return t, nil
	}
	if writeTerminal(w) || w.Journal.Pending == nil {
		return t, ErrPolicy
	}
	journal, err := reconcile.Settle(w.Journal, p.Operation, p.Outcome)
	if err != nil {
		return t, err
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	w = ownWrite(w)
	w.Journal = journal
	p.Request = ownRequest(p.Request)
	p.Signature = slices.Clone(p.Signature)
	w.Observation = &p
	n.writes[w.Request.ID] = w
	return n, nil
}

// PublishStored uses the ORIGINAL receipt. Controllers initially use the
// captured object CAS; accepting a newer CAS must be an explicit authorized
// management decision, never an automatic retry with a new provider write.
func (t Tree) PublishStored(c access.Catalog, actor, id string, epoch, expectedObject, expectedTree uint64) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	if expectedTree != t.revision || epoch != t.writeEpoch {
		return t, access.ErrConflict
	}
	w, ok := t.writes[id]
	if !ok || w.Abandoned {
		return t, ErrPolicy
	}
	if w.PublishedRevision != 0 {
		return t, nil
	}
	o, ok := t.objects[w.Request.Object]
	if !ok || o.Generation != w.Generation || o.Revision != expectedObject || o.PendingWrite != id {
		return t, access.ErrConflict
	}
	if w.Journal.Pending != nil || !w.Journal.Applied.Present || w.Observation == nil || w.Observation.Outcome != reconcile.EffectApplied {
		return t, ErrPolicy
	}
	p, ok := t.profile(w.Request.Profile)
	if !ok || !p.Enabled || w.Request.Kind == ValueWrite && !p.Values || w.Request.Kind == VerifierWrite && !p.Verifiers {
		return t, access.ErrDenied
	}
	n := t
	o = ownObject(o)
	o.PendingWrite = ""
	n.objects = map[string]Object{}
	for k, v := range t.objects {
		n.objects[k] = ownObject(v)
	}
	n.objects[o.ID] = o
	var result Tree
	var err error
	if w.Request.Kind == ValueWrite {
		result, err = n.PublishReference(c, actor, o.ID, expectedObject, Reference{Profile: w.Request.Profile, Object: w.Request.ProviderObject, Revision: w.Observation.ProviderRevision, Keys: w.Request.Keys})
	} else {
		if w.Request.Protected && w.Observation.VerifierRef == o.VerifierRef {
			return t, ErrPolicy
		}
		result, err = n.ActivatePassword(c, actor, o.ID, w.Request.ID, w.Observation.VerifierRef, w.Request.Protected, expectedObject)
	}
	if err != nil {
		return t, err
	}
	if w.Request.Kind == VerifierWrite && w.Request.Protected && w.Request.ProviderObject == verifierObject(t.tenant, w.Request.Object, w.Generation) {
		o := result.objects[w.Request.Object]
		o.VerifierBinding = &VerifierBinding{Reference: Reference{Profile: w.Request.Profile, Object: w.Request.ProviderObject, Revision: w.Observation.ProviderRevision, Keys: []string{"verifier"}}, Receipt: writeReceipt(w)}
		result.objects[o.ID] = o
	}
	if w.Writer.Builtin() {
		h := BuiltinHolding{Kind: w.Request.Kind, Object: w.Request.ProviderObject, Revision: w.Observation.ProviderRevision, Digest: w.Observation.Digest}
		for _, r := range w.Observation.Holders {
			h.Holders = append(h.Holders, r.Voter)
		}
		if _, exists := result.builtin[h.key()]; exists || len(result.builtin) >= maxBuiltinHoldings || !h.valid() {
			return t, ErrPolicy
		}
		result.builtin[h.key()] = h
	}
	w = ownWrite(w)
	w.PublishedRevision = result.revision
	result.writes[id] = w
	return result, nil
}

// AbandonWrite never destroys a provider revision. Dispatched/unknown work must
// first settle. Immutable previous verifier references remain safe to use after
// an explicit abandonment; the policy revision advances so old approvals fail.
func (t Tree) AbandonWrite(c access.Catalog, actor, id string, epoch, expected uint64) (Tree, error) {
	allowed := c.AuthorizeCleanup(actor, t.tenant, access.ManageSecrets) == nil
	if t.tenant == "" {
		allowed = c.SystemAllowed(actor)
	}
	if !allowed {
		return t, access.ErrDenied
	}
	if expected != t.revision || epoch != t.writeEpoch {
		return t, access.ErrConflict
	}
	w, ok := t.writes[id]
	if !ok || w.PublishedRevision != 0 {
		return t, ErrPolicy
	}
	if w.Abandoned {
		return t, nil
	}
	var err error
	if w.Journal.Pending != nil {
		if w.Journal.Pending.Phase != reconcile.Prepared {
			return t, reconcile.ErrPending
		}
		w.Journal, err = reconcile.AbortPrepared(w.Journal, w.Journal.Pending.ID)
		if err != nil {
			return t, err
		}
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	w = ownWrite(w)
	w.Abandoned = true
	n.writes[id] = w
	o := ownObject(n.objects[w.Request.Object])
	if o.PendingWrite == id {
		o.PendingWrite = ""
		if w.Request.Kind == VerifierWrite && o.PasswordChange == id {
			o.PasswordChange = ""
			if o.Status == PasswordPending {
				o.Status = Active
			}
			o.PolicyRevision = n.revision
			o.AuthPolicy = n.revision
		}
		o.Revision = n.revision
		n.objects[o.ID] = o
	}
	return n, nil
}
func (t Tree) RotateWrites(c access.Catalog, actor string, expected, epoch uint64) (Tree, error) {
	if !t.managed(c, actor) {
		return t, access.ErrDenied
	}
	if expected != t.revision || epoch != t.writeEpoch {
		return t, access.ErrConflict
	}
	if epoch == ^uint64(0) {
		return t, ErrPolicy
	}
	for _, w := range t.writes {
		if !writeTerminal(w) {
			return t, reconcile.ErrPending
		}
	}
	for _, o := range t.objects {
		if o.PendingWrite != "" || o.PasswordChange != "" {
			return t, reconcile.ErrPending
		}
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	n.writeEpoch++
	n.writes = map[string]WriteRecord{}
	return n, nil
}
func (t Tree) validWrite(w WriteRecord) bool {
	r := w.Request
	o, ok := t.objects[r.Object]
	if !ok || !identifier(r.ID) || r.Epoch != t.writeEpoch || !identifier(w.Actor) || w.Generation != o.Generation || w.ExpectedObjectRevision == 0 || w.ExpectedObjectRevision > t.revision || !usableProfile(w.Writer) || w.Writer.Mode == "local-file" || w.Writer.ID != r.Profile || w.Writer.Revision > t.revision || !cleanText(r.ProviderObject) || r.Kind != ValueWrite && r.Kind != VerifierWrite || reconcile.Validate(w.Journal) != nil || w.Journal.LastID != 1 || w.Journal.Desired.Spec != writeSpec(t.cluster, t.tenant, w) || w.Journal.Desired.Generation != w.Generation || !w.Journal.Desired.Present || w.Journal.Applied.Present && w.Journal.Applied != w.Journal.Desired.Resource || w.PublishedRevision > t.revision || w.Abandoned && w.PublishedRevision != 0 {
		return false
	}
	if r.Kind == ValueWrite {
		v, err := referenceShape(Reference{Profile: r.Profile, Object: r.ProviderObject, Revision: r.ExpectedProviderRevision, Keys: r.Keys})
		if err != nil || !slices.Equal(v.Keys, r.Keys) || r.Protected || o.Kind != Secret || !w.Writer.Values {
			return false
		}
	} else if o.Kind != Group || len(r.Keys) != 0 || r.ProviderObject != verifierObject(t.tenant, o.ID, o.Generation) && !(t.tenant == "" && r.ProviderObject == "groups/cluster/"+o.ID+"/"+strconv.FormatUint(o.Generation, 10)) || !w.Writer.Verifiers {
		return false
	}
	if w.Observation != nil && !t.validObservation(w, *w.Observation) {
		return false
	}
	if w.Journal.Desired.Revision > t.revision || w.Journal.GenerationFloor != w.Generation || w.Journal.Stopped || w.Journal.Desired.Retiring != 0 {
		return false
	}
	if p := w.Journal.Pending; p != nil && (p.Kind != reconcile.Apply || p.Target != w.Journal.Desired.Resource) {
		return false
	}
	if w.Observation != nil {
		switch w.Observation.Outcome {
		case reconcile.EffectUnknown:
			if w.Journal.Pending == nil || w.Journal.Pending.Phase != reconcile.RecoveryRequired {
				return false
			}
		case reconcile.EffectApplied:
			if w.Journal.Pending != nil || !w.Journal.Applied.Present {
				return false
			}
		case reconcile.EffectNotApplied:
			if w.Journal.Pending != nil || w.Journal.Applied.Present {
				return false
			}
		}
	} else if w.Journal.Pending != nil && w.Journal.Pending.Phase == reconcile.RecoveryRequired {
		return false
	}
	if w.Journal.Applied.Present && (w.Observation == nil || w.Observation.Outcome != reconcile.EffectApplied) {
		return false
	}
	if w.Journal.Pending == nil && !w.Journal.Applied.Present && !w.Abandoned && (w.Observation == nil || w.Observation.Outcome != reconcile.EffectNotApplied) {
		return false
	}
	if w.PublishedRevision != 0 && (!w.Journal.Applied.Present || w.Journal.Pending != nil) || w.Abandoned && w.Journal.Pending != nil {
		return false
	}
	if !writeTerminal(w) && (o.PendingWrite != r.ID || o.Status == Retired) {
		return false
	}
	return true
}
