// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/userauth"
)

// builtinValueRequest is the VaultValue body: a writing voter asking another
// current voter to store a sealed value of a Dispatched builtin write.
// Fetch instead asks a holder for the sealed value of a published revision,
// so a voter that lacks it can fill it in.
type builtinValueRequest struct {
	Schema    uint8
	Replicate *secrets.BuiltinValue `json:",omitempty"`
	Fetch     *builtinFetch         `json:",omitempty"`
}
type builtinFetch struct {
	Realm  string
	Digest [32]byte
}

// builtinValueReply is a holder's signed statement for the stored value,
// or for a fetch the sealed value itself.
type builtinValueReply struct {
	Schema uint8
	Holder secrets.HolderReceipt
	Value  *secrets.BuiltinValue `json:",omitempty"`
}

// builtinWrite seals, stores and replicates one builtin write on this voter
// and reports it Applied once a majority of the current voters hold it.
// Without a majority it stays Unknown: recover continues with the same
// sealed value and never takes new input.
func (r *Runtime) builtinWrite(ctx context.Context, permit control.VaultWritePermit, q userauth.SecretRequest) (secrets.WriteObservation, error) {
	w := permit.Record
	self := r.commandIdentity()
	fact := secrets.WriteObservation{Cluster: permit.Cluster, Tenant: q.Realm, Request: w.Request, Generation: w.Generation, ExpectedObjectRevision: w.ExpectedObjectRevision, Writer: w.Writer, Operation: w.Journal.LastID, Outcome: reconcile.EffectUnknown, Reporter: self.Public}
	sign := func(err error) (secrets.WriteObservation, error) {
		fact.Signature = ed25519.Sign(self.Private, secrets.WriteObservationBytes(fact))
		return fact, err
	}
	if w.Observation != nil && w.Observation.Outcome == reconcile.EffectApplied {
		// Already settled in Raft: the committed fact is the answer.
		return *w.Observation, nil
	}
	if r.builtinValues == nil {
		return sign(secrets.ErrProvider)
	}
	writeKey := secrets.BuiltinWriteKey(permit.Cluster, q.Realm, w)
	v, err := r.builtinValues.ForWrite(writeKey)
	switch {
	case err == nil:
		if !v.Binds(permit.Cluster, q.Realm, w) || v.Sealer != self.Public {
			log.Printf("vault write %s/%s: the local builtin value does not match this write", q.Realm, q.ID)
			return sign(secrets.ErrProvider)
		}
	case !errors.Is(err, storage.ErrMissing):
		log.Printf("vault write %s/%s: builtin store: %v", q.Realm, q.ID, err)
		return sign(secrets.ErrProvider)
	case q.Mode == "recover" || w.Status() != "Dispatched":
		// Nothing was sealed here; whoever sealed it must continue.
		log.Printf("vault write %s/%s: no local builtin value to recover", q.Realm, q.ID)
		return sign(secrets.ErrProvider)
	default:
		values := q.Values
		if w.Request.Kind == secrets.VerifierWrite && w.Request.Protected {
			if _, err := identity.RestorePasswordVerifier(values["verifier"]); err != nil {
				log.Printf("vault write %s/%s: bad password verifier input", q.Realm, q.ID)
				return sign(secrets.ErrProvider)
			}
		}
		master, err := r.certificateMaster()
		if err != nil {
			log.Printf("vault write %s/%s: this voter has no master key yet", q.Realm, q.ID)
			return sign(secrets.ErrProvider)
		}
		v, err = secrets.SealBuiltinValue(master, permit.Cluster, q.Realm, w, self.Public, values)
		clear(master)
		if err != nil {
			log.Printf("vault write %s/%s: the values do not fit this write (keys or size)", q.Realm, q.ID)
			// Refused before anything was stored: the write did not happen.
			fact.Outcome = reconcile.EffectNotApplied
			return sign(secrets.ErrProvider)
		}
		if err = r.builtinValues.Put(writeKey, v); err != nil {
			log.Printf("vault write %s/%s: builtin store: %v", q.Realm, q.ID, err)
			return sign(secrets.ErrProvider)
		}
	}
	holders, err := r.replicateBuiltin(ctx, v)
	if err != nil {
		log.Printf("vault write %s/%s: builtin value held by %d voters, not a majority yet: %v", q.Realm, q.ID, len(holders), err)
		return sign(secrets.ErrProvider)
	}
	fact.Outcome = reconcile.EffectApplied
	receipt := secrets.BuiltinReceipt(v)
	fact.ProviderRevision = receipt.Revision
	fact.Digest = v.Digest()
	fact.Holders = holders
	if w.Request.Kind == secrets.VerifierWrite && w.Request.Protected {
		if fact.VerifierRef, err = receipt.VerifierReference(); err != nil {
			fact = secrets.WriteObservation{Cluster: fact.Cluster, Tenant: fact.Tenant, Request: fact.Request, Generation: fact.Generation, ExpectedObjectRevision: fact.ExpectedObjectRevision, Writer: fact.Writer, Operation: fact.Operation, Outcome: reconcile.EffectUnknown, Reporter: fact.Reporter}
			return sign(secrets.ErrProvider)
		}
	}
	return sign(nil)
}

// replicateBuiltin collects holder receipts for v: this voter's own and those
// of the other current voters that store it. It returns them sorted, and an
// error unless they are a majority of the current voters.
func (r *Runtime) replicateBuiltin(ctx context.Context, v secrets.BuiltinValue) ([]secrets.HolderReceipt, error) {
	self := r.commandIdentity()
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return nil, sfcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.VoterKey(self.Public) {
		return nil, sfcp.ErrAdmission
	}
	voters := members.SessionIssuers()
	holders := []secrets.HolderReceipt{{Voter: self.Public, Signature: ed25519.Sign(self.Private, v.HolderBytes(self.Public))}}
	body, err := json.Marshal(builtinValueRequest{Schema: 1, Replicate: &v})
	if err != nil {
		return nil, err
	}
	for _, peer := range r.voterPeers(members) {
		if len(holders)*2 > len(voters) {
			break
		}
		voter := [32]byte(peer.Key)
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		raw, err := r.callVaultValue(call, peer, body)
		cancel()
		if err != nil {
			continue
		}
		reply, err := schema.Decode[builtinValueReply](raw)
		if err != nil || reply.Schema != 1 || reply.Holder.Voter != voter || !ed25519.Verify(ed25519.PublicKey(voter[:]), v.HolderBytes(voter), reply.Holder.Signature) {
			continue
		}
		holders = append(holders, reply.Holder)
	}
	slices.SortFunc(holders, func(a, b secrets.HolderReceipt) int { return slices.Compare(a.Voter[:], b.Voter[:]) })
	if len(holders)*2 <= len(voters) {
		return holders, sfcp.ErrAdmission
	}
	return holders, nil
}

// voterPeers lists the other current voters reachable as members, by ID.
func (r *Runtime) voterPeers(members membership.Directory) []sfcp.Peer {
	peers := []sfcp.Peer{}
	for _, entry := range members.Entries {
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil || key == r.commandIdentity().Public || !members.VoterKey(key) {
			continue
		}
		if peer, ok := r.Mesh.Peer(sfcp.Identity(key)); ok && peer.Member {
			peers = append(peers, peer)
		}
	}
	slices.SortFunc(peers, func(a, b sfcp.Peer) int { return strings.Compare(a.ID, b.ID) })
	return peers
}

func (r *Runtime) callVaultValue(ctx context.Context, peer sfcp.Peer, body []byte) ([]byte, error) {
	session, err := r.Mesh.Dial(ctx, peer)
	if err != nil {
		return nil, err
	}
	return session.CallVaultValue(ctx, body)
}

// serveVaultValue stores a sealed value for a writing voter. Both ends must
// be current voters and the write Dispatched (or Unknown) with the same
// public receipt. The value is never opened here.
func (r *Runtime) serveVaultValue() error {
	return r.Mesh.OnVaultValue(func(ctx context.Context, s *sfcp.Session, body []byte) ([]byte, error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(r.ctx, cancel)
		defer stop()
		q, err := schema.Decode[builtinValueRequest](body)
		if err != nil || q.Schema != 1 || (q.Replicate == nil) == (q.Fetch == nil) {
			return nil, sfcp.ErrAdmission
		}
		if q.Fetch != nil {
			return r.serveBuiltinFetch(ctx, [32]byte(s.Peer().Key), *q.Fetch)
		}
		v := *q.Replicate
		caller := [32]byte(s.Peer().Key)
		self := r.commandIdentity()
		r.life.RLock()
		defer r.life.RUnlock()
		if r.closed || r.reports == nil || r.builtinValues == nil || v.Sealer != caller {
			return nil, sfcp.ErrAdmission
		}
		view, err := r.physicalOwners()[0].currentView(ctx)
		if err != nil || view.Local {
			return nil, sfcp.ErrAdmission
		}
		members, err := r.controlPolicy.Members(view.State)
		if err != nil || !members.VoterKey(caller) || !members.VoterKey(self.Public) {
			return nil, sfcp.ErrAdmission
		}
		vault, err := r.controlPolicy.Vault(view.State)
		if err != nil {
			return nil, sfcp.ErrAdmission
		}
		tree, ok := vault.Trees[v.Realm]
		if !ok {
			return nil, sfcp.ErrAdmission
		}
		w, ok := tree.Write(v.Write)
		if !ok || w.Status() != "Dispatched" && w.Status() != "Unknown" || !v.Binds(r.controlPolicy.Cluster, v.Realm, w) {
			return nil, sfcp.ErrAdmission
		}
		if err = r.builtinValues.Put(secrets.BuiltinWriteKey(r.controlPolicy.Cluster, v.Realm, w), v); err != nil {
			log.Printf("vault value %s/%s: refused to hold: %v", v.Realm, v.Write, err)
			return nil, sfcp.ErrAdmission
		}
		return json.Marshal(builtinValueReply{Schema: 1, Holder: secrets.HolderReceipt{Voter: self.Public, Signature: ed25519.Sign(self.Private, v.HolderBytes(self.Public))}})
	})
}

// openBuiltinLeaf opens the published builtin revision of permit from this
// voter's local store. The caller holds r.life and clears the values.
func (r *Runtime) openBuiltinLeaf(permit control.AppInputFetchPermit) (secrets.Fetched, error) {
	h := permit.Builtin
	if h == nil || r.builtinValues == nil || h.Kind != secrets.ValueWrite || h.Object != permit.Leaf.Reference.Object || h.Revision != permit.Leaf.Reference.Revision {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	v, err := r.builtinValues.Get(h.Digest)
	if err != nil || v.Cluster != r.controlPolicy.Cluster || v.Realm != permit.Realm || v.Kind != secrets.ValueWrite || v.Object != h.Object || v.Revision != h.Revision || !slices.Equal(v.Keys, permit.Leaf.Reference.Keys) {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	master, err := r.certificateMaster()
	if err != nil {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	defer clear(master)
	values, err := secrets.OpenBuiltinValue(master, v)
	if err != nil {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	return secrets.Fetched{Secret: permit.Leaf.Secret, Reference: permit.Leaf.Reference, Values: values}, nil
}

// fetchBuiltinLeaf reads a builtin leaf here when this node is a voter that
// holds it, else from the other current voters, holders first. Every voter
// asked checks its own permit for this consumer again.
func (r *Runtime) fetchBuiltinLeaf(ctx context.Context, q control.AppInputFetch) (secrets.Fetched, error) {
	view, members, err := r.members(ctx, false)
	if err != nil {
		return secrets.Fetched{}, err
	}
	self := r.commandIdentity().Public
	if members.VoterKey(self) {
		if value, err := r.readAppInputLeaf(ctx, q); err == nil {
			return value, nil
		}
	}
	var holders [][32]byte
	// Holders of the current revision go first; a pinned older revision is
	// still asked of every voter.
	if v, err := r.controlPolicy.Vault(view.State); err == nil {
		if o, ok := v.Trees[q.Realm].Object(q.Secret); ok {
			if h, ok := v.Trees[q.Realm].BuiltinHolding(secrets.ValueWrite, o.Reference.Object, o.Reference.Revision); ok {
				holders = h.Holders
			}
		}
	}
	peers := r.voterPeers(members)
	slices.SortStableFunc(peers, func(a, b sfcp.Peer) int {
		ha, hb := slices.Contains(holders, [32]byte(a.Key)), slices.Contains(holders, [32]byte(b.Key))
		switch {
		case ha && !hb:
			return -1
		case hb && !ha:
			return 1
		}
		return 0
	})
	failure := error(secrets.ErrProvider)
	for _, peer := range peers {
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		value, err := r.fetchAppInputFrom(call, q, peer)
		cancel()
		if err == nil {
			return value, nil
		}
		failure = err
	}
	return secrets.Fetched{}, failure
}

// openBuiltinVerifier opens a group's builtin password verifier from this
// voter's local store, by the digest Raft holds for binding.
func (r *Runtime) openBuiltinVerifier(ctx context.Context, realm string, binding secrets.VerifierBinding) (secrets.Fetched, error) {
	if r.builtinValues == nil {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	vault, err := r.controlPolicy.Vault(view.State)
	if err != nil {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	h, ok := vault.Trees[realm].BuiltinHolding(secrets.VerifierWrite, binding.Reference.Object, binding.Reference.Revision)
	if !ok {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	v, err := r.builtinValues.Get(h.Digest)
	if err != nil || v.Cluster != r.controlPolicy.Cluster || v.Realm != realm || v.Kind != secrets.VerifierWrite || v.Object != h.Object || v.Revision != h.Revision || v.Receipt != binding.Receipt {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	master, err := r.certificateMaster()
	if err != nil {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	defer clear(master)
	values, err := secrets.OpenBuiltinValue(master, v)
	if err != nil {
		return secrets.Fetched{}, secrets.ErrProvider
	}
	return secrets.Fetched{Reference: binding.Reference, Values: values}, nil
}
