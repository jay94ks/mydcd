// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// fakeVaultWrite models one provider write of the real five-step protocol.
// Values are never kept: only the key names that arrived, for tests.
type fakeVaultWrite struct {
	req                secrets.WriteRequest
	status             string // Prepared, Dispatched, StoredUnreferenced, NotApplied, Published
	generation, objRev uint64
	operation          uint64
	attempted          bool
	obs                *secrets.WriteObservation
	received           []string
	verifier           *identity.PasswordVerifier // a Group password write (the verifier, not the password)
}

func fakeWriter() secrets.WriteProfile {
	return secrets.WriteProfile{ID: "default", Node: "node-a", Key: [32]byte(FixtureKey("vault-writer").Public().(ed25519.PublicKey)), Revision: 1, Enabled: true, Values: true, Verifiers: true}
}

func (w *world) vaultRow(realm, object string) int {
	return slices.IndexFunc(w.vault, func(v VaultView) bool { return v.Realm == realm && path.Base(v.Path) == object })
}

func (c *fakeConn) PlanVaultWrite(ctx context.Context, tenant string, q VaultWritePlanRequest) (VaultWritePlan, error) {
	const m = "vault-write-plan"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return VaultWritePlan{}, err
	}
	defer c.unlock()
	w := c.f.w
	if q.Realm != tenant || !w.canManageRealm(user, tenant) {
		return VaultWritePlan{}, fail(m, CodeDenied, "")
	}
	pub := hex.EncodeToString(FixtureKey("vault-writer").Public().(ed25519.PublicKey))
	plan := VaultWritePlan{Schema: 1, Realm: q.Realm, RootRevision: w.root, TreeRevision: w.vaultRev[q.Realm], WriteEpoch: 1,
		Receiver: &config.Peer{ID: "node-a", Key: pub, Endpoint: "node-a.mydc.invalid:7443"}}
	if fw := w.vaultWrites[q.Realm+"/"+q.ID]; fw != nil {
		plan.Request = fw.req
		plan.Write = &VaultWriteView{Request: fw.req, Actor: user, Generation: fw.generation, ExpectedObjectRevision: fw.objRev, Writer: fakeWriter(), Operation: fw.operation, Status: fw.status}
		if fw.status == "StoredUnreferenced" || fw.status == "Published" || fw.status == "NotApplied" {
			plan.Observation = fw.obs
		}
		return plan, nil
	}
	if q.Object == "" && q.Kind == "" {
		return plan, nil // a status read of an unknown write
	}
	i := w.vaultRow(q.Realm, q.Object)
	if i < 0 || q.ID == "" {
		return VaultWritePlan{}, fail(m, CodeInvalid, "object")
	}
	row := w.vault[i]
	r := secrets.WriteRequest{ID: q.ID, Object: q.Object, Profile: "default", Epoch: 1, Kind: q.Kind}
	switch q.Kind {
	case secrets.ValueWrite:
		if row.Kind != "object" {
			return VaultWritePlan{}, fail(m, CodeInvalid, "not a secret")
		}
		r.Profile, r.ProviderObject, r.Keys = row.Profile, row.Realm+"/"+row.Path, slices.Clone(q.Keys)
		if len(r.Keys) == 0 {
			r.Keys = slices.Clone(row.Keys)
		}
		slices.Sort(r.Keys)
	case secrets.VerifierWrite:
		if row.Kind != "group" {
			return VaultWritePlan{}, fail(m, CodeInvalid, "not a group")
		}
		r.ProviderObject, r.Protected = "verifier/"+row.Realm+"/"+row.Path, true
	default:
		return VaultWritePlan{}, fail(m, CodeInvalid, "kind")
	}
	plan.Request = r
	return plan, nil
}

func (c *fakeConn) WriteVault(ctx context.Context, tenant string, receiver config.Peer, q SecretWrite) (SecretWriteReply, error) {
	const m = "secret-input"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return SecretWriteReply{}, err
	}
	defer c.unlock()
	w := c.f.w
	fw := w.vaultWrites[q.Realm+"/"+q.ID]
	if q.Realm != tenant || receiver.ID != "node-a" || fw == nil || !w.canManageRealm(user, tenant) {
		return SecretWriteReply{Code: "denied"}, nil
	}
	if fw.status != "Dispatched" {
		return SecretWriteReply{Code: "ok", Observation: fw.obs}, nil
	}
	obs := &secrets.WriteObservation{Cluster: w.cluster, Tenant: q.Realm, Request: fw.req, Generation: fw.generation, ExpectedObjectRevision: fw.objRev,
		Writer: fakeWriter(), Operation: fw.operation, Observer: fakeWriter(), Outcome: reconcile.EffectNotApplied}
	switch {
	case q.Mode == "execute" && !fw.attempted:
		keys := []string{}
		for k := range q.Values {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		want := fw.req.Keys
		if fw.req.Kind == secrets.VerifierWrite {
			want = []string{"verifier"}
		}
		if !slices.Equal(keys, want) {
			return SecretWriteReply{Code: "denied"}, nil
		}
		fw.attempted, fw.received = true, keys
		if fw.req.Kind == secrets.VerifierWrite {
			v, err := identity.RestorePasswordVerifier(q.Values["verifier"])
			if err != nil {
				return SecretWriteReply{Code: "denied"}, nil
			}
			fw.verifier = &v
		}
		obs.Outcome, obs.ProviderRevision = reconcile.EffectApplied, 1
		if fw.req.Kind == secrets.VerifierWrite {
			obs.VerifierRef = "vref-" + fw.req.ID
		}
	case q.Mode == "recover" && fw.attempted:
		return SecretWriteReply{Code: "ok", Observation: fw.obs}, nil
	case q.Mode == "recover":
		// nothing arrived: a positive not-applied observation
	default:
		return SecretWriteReply{Code: "denied"}, nil
	}
	obs.Signature = ed25519.Sign(FixtureKey("vault-writer"), secrets.WriteObservationBytes(*obs))
	fw.obs = obs
	return SecretWriteReply{Code: "ok", Observation: obs}, nil
}

// VaultWriteReceived returns the key names (never values) that reached the
// fake receiver for a write, for tests.
func (f *Fake) VaultWriteReceived(realm, id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fw := f.w.vaultWrites[realm+"/"+id]; fw != nil {
		return slices.Clone(fw.received)
	}
	return nil
}

// applyVaultWrite models the four original steps of a provider write.
// f.mu is held.
func (c *fakeConn) applyVaultWrite(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var realm, id string
	switch ch.Action {
	case ActionVaultPrepareWrite:
		var v control.VaultWrite
		if decodePayload(ch.Payload, &v) != nil {
			return errors.New("payload")
		}
		realm, id = v.Realm, v.Request.ID
		if !w.canManageRealm(actor, realm) {
			return errForbidden
		}
		i := w.vaultRow(realm, v.Request.Object)
		if ch.Expected != w.vaultRev[realm] || w.vaultWrites[realm+"/"+id] != nil || i < 0 {
			return errCAS
		}
		w.vaultWrites[realm+"/"+id] = &fakeVaultWrite{req: v.Request, status: "Prepared", generation: 1, objRev: w.vault[i].Revision, operation: next}
	case ActionVaultDispatchWrite, ActionVaultPublishWrite:
		var v control.VaultWriteAction
		if decodePayload(ch.Payload, &v) != nil {
			return errors.New("payload")
		}
		realm, id = v.Realm, v.ID
		if !w.canManageRealm(actor, realm) {
			return errForbidden
		}
		fw := w.vaultWrites[realm+"/"+id]
		if ch.Expected != w.vaultRev[realm] || fw == nil || v.Epoch != fw.req.Epoch {
			return errCAS
		}
		if ch.Action == ActionVaultDispatchWrite {
			if fw.status != "Prepared" {
				return errors.New("phase")
			}
			fw.status = "Dispatched"
			break
		}
		i := w.vaultRow(realm, fw.req.Object)
		if fw.status != "StoredUnreferenced" || i < 0 || v.ObjectRevision != w.vault[i].Revision {
			return errCAS
		}
		fw.status = "Published"
		w.vault[i].Revision = next
		if fw.req.Kind == secrets.VerifierWrite {
			w.vault[i].Protected = true
			if fw.verifier != nil {
				w.groupVerifiers[realm+"/"+fw.req.Object] = *fw.verifier
			}
		}
	case ActionVaultObserveWrite:
		var v control.VaultObserve
		if decodePayload(ch.Payload, &v) != nil {
			return errors.New("payload")
		}
		realm, id = v.Observation.Tenant, v.Observation.Request.ID
		fw := w.vaultWrites[realm+"/"+id]
		if ch.Expected != w.vaultRev[realm] || fw == nil || fw.status != "Dispatched" || fw.obs == nil {
			return errCAS
		}
		if v.Observation.Operation != fw.obs.Operation || v.Observation.Outcome != fw.obs.Outcome || !ed25519.Verify(fw.obs.Writer.Key[:], secrets.WriteObservationBytes(v.Observation), v.Observation.Signature) {
			return errors.New("observation")
		}
		fw.status = "StoredUnreferenced"
		if fw.obs.Outcome != reconcile.EffectApplied {
			fw.status = "NotApplied"
		}
	default:
		return errors.New("action")
	}
	w.vaultRev[realm] = next
	return nil
}
