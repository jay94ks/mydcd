// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// builtinFillsPerTick bounds how many missing values one tick fills in.
const builtinFillsPerTick = 8

// serveBuiltinFetch gives a current voter the sealed value of a published
// builtin revision this voter holds. The value stays sealed.
func (r *Runtime) serveBuiltinFetch(ctx context.Context, caller [32]byte, q builtinFetch) ([]byte, error) {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.reports == nil || r.builtinValues == nil {
		return nil, sfcp.ErrAdmission
	}
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return nil, sfcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.VoterKey(caller) || !members.VoterKey(r.commandIdentity().Public) {
		return nil, sfcp.ErrAdmission
	}
	vault, err := r.controlPolicy.Vault(view.State)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	tree, ok := vault.Trees[q.Realm]
	if !ok || !slices.ContainsFunc(tree.BuiltinHoldings(), func(h secrets.BuiltinHolding) bool { return h.Digest == q.Digest }) {
		return nil, sfcp.ErrAdmission
	}
	v, err := r.builtinValues.Get(q.Digest)
	if err != nil || v.Realm != q.Realm {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(builtinValueReply{Schema: 1, Value: &v})
}

// advanceBuiltinVault keeps the builtin values on exactly the current voters:
// a voter fills in published revisions it lacks from a holder and reports
// itself as a holder; every voter deletes values nothing can read any more;
// a node that stopped being a voter deletes them all.
func (r *Runtime) advanceBuiltinVault(ctx context.Context) {
	if r.historicalOwner || r.reports == nil || r.builtinValues == nil || time.Since(r.builtinUpkeepAt) < 30*time.Second {
		return
	}
	r.builtinUpkeepAt = time.Now()
	self := r.commandIdentity().Public
	// Taken before any state is read: a value stored after it (a write
	// replicated meanwhile, already receipted) is never deleted this tick.
	mark := r.builtinValues.Mark()
	_, local, err := r.members(ctx, false)
	if err != nil {
		return
	}
	if !local.VoterKey(self) {
		if certificateNonVoter(local, self) {
			if n, err := r.builtinValues.Retain(nil, mark); err == nil && n > 0 {
				log.Printf("builtin vault: not a voter; deleted %d local values", n)
			}
		}
		return
	}
	// Deleting and reporting use the quorum view, never a lagging local one.
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.VoterKey(self) {
		return
	}
	vault, err := r.controlPolicy.Vault(view.State)
	if err != nil {
		return
	}
	keep := map[[32]byte]bool{}
	fills := 0
	for realm, tree := range vault.Trees {
		for _, h := range tree.BuiltinHoldings() {
			keep[h.Digest] = true
			held, listed := r.builtinValues.Has(h.Digest), slices.Contains(h.Holders, self)
			if held && listed || fills >= builtinFillsPerTick {
				continue
			}
			fills++
			if !held && !r.fillBuiltin(ctx, members, realm, h) || listed {
				continue
			}
			if err := r.reportBuiltinHolder(ctx, view.State, realm, h); err != nil {
				log.Printf("builtin vault: holder report for %s %s/%d: %v", realm, h.Object, h.Revision, err)
			}
		}
		// A value of a write still on its way to Raft is kept too.
		for _, w := range tree.Writes() {
			if w.Writer.Builtin() && w.Status() == "StoredUnreferenced" && w.Observation != nil {
				keep[w.Observation.Digest] = true
			}
			if w.Writer.Builtin() && (w.Status() == "Dispatched" || w.Status() == "Unknown") {
				if v, err := r.builtinValues.ForWrite(secrets.BuiltinWriteKey(r.controlPolicy.Cluster, realm, w)); err == nil {
					keep[v.Digest()] = true
				}
			}
		}
	}
	if n, err := r.builtinValues.Retain(keep, mark); err == nil && n > 0 {
		log.Printf("builtin vault: deleted %d local values nothing reads", n)
	}
}

// fillBuiltin copies the sealed value of h from a holder voter, checking that
// it is exactly the published revision.
func (r *Runtime) fillBuiltin(ctx context.Context, members membership.Directory, realm string, h secrets.BuiltinHolding) bool {
	body, _ := json.Marshal(builtinValueRequest{Schema: 1, Fetch: &builtinFetch{Realm: realm, Digest: h.Digest}})
	for _, peer := range r.voterPeers(members) {
		if !slices.Contains(h.Holders, [32]byte(peer.Key)) {
			continue
		}
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		raw, err := r.callVaultValue(call, peer, body)
		cancel()
		if err != nil {
			continue
		}
		reply, err := schema.Decode[builtinValueReply](raw)
		if err != nil || reply.Value == nil {
			continue
		}
		v := *reply.Value
		if v.Digest() != h.Digest || v.Cluster != r.controlPolicy.Cluster || v.Realm != realm || v.Kind != h.Kind || v.Object != h.Object || v.Revision != h.Revision {
			continue
		}
		if err = r.builtinValues.Put("held/"+v.StoreKey(), v); err != nil {
			log.Printf("builtin vault: cannot store %s %s/%d: %v", realm, h.Object, h.Revision, err)
			return false
		}
		return true
	}
	return false
}

func (r *Runtime) reportBuiltinHolder(ctx context.Context, s state.State, realm string, h secrets.BuiltinHolding) error {
	self := r.commandIdentity()
	report := control.VaultHolderReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: self.Public, RootRevision: s.Object(control.VaultKey).Revision, Epoch: s.ModuleEpoch(), At: uint64(time.Now().Unix()), Realm: realm, Kind: h.Kind, Object: h.Object, Revision: h.Revision, Digest: h.Digest}
	report.Signature = ed25519.Sign(self.Private, control.VaultHolderBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = r.appCall(ctx, "vault-holder-report", raw)
	return err
}
