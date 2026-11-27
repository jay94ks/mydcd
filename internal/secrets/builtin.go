// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// BuiltinProfile is the write profile every tree has: values and group
// verifiers kept sealed in the local stores of the current voters. It names
// no node; any voter that holds the cluster master key writes and serves it.
// An installed profile cannot use this name.
const BuiltinProfile = "builtin"

// BuiltinWriteProfile is the one builtin profile value.
func BuiltinWriteProfile() WriteProfile {
	return WriteProfile{Mode: BuiltinProfile, ID: BuiltinProfile, Revision: 1, Enabled: true, Values: true, Verifiers: true}
}

// Builtin reports whether p is the builtin profile.
func (p WriteProfile) Builtin() bool { return p == BuiltinWriteProfile() }

// HolderReceipt is a voter's signed statement that it durably stores the
// sealed value of one builtin write: the bytes whose SHA-256 is Digest.
type HolderReceipt struct {
	Voter     [32]byte
	Signature []byte
}

// HolderBytes is what a holder signs for observation p.
func HolderBytes(p WriteObservation, voter [32]byte) []byte {
	v := struct {
		Cluster         [32]byte
		Tenant          string
		ID              string
		Epoch, Revision uint64
		Object          string
		Digest          [32]byte
		Voter           [32]byte
	}{p.Cluster, p.Tenant, p.Request.ID, p.Request.Epoch, p.ProviderRevision, p.Request.ProviderObject, p.Digest, voter}
	b, _ := json.Marshal(v)
	return append([]byte("sfc-secret-builtin-holder-1\x00"), b...)
}

// validBuiltinObservation checks signatures and shape only. Whether the
// reporter and holders are current voters, and a majority of them, is the
// control policy's check: the tree does not know the membership.
func validBuiltinObservation(w WriteRecord, p WriteObservation) bool {
	if p.Observer != (WriteProfile{}) || p.Reporter == ([32]byte{}) || !ed25519.Verify(ed25519.PublicKey(p.Reporter[:]), WriteObservationBytes(p), p.Signature) {
		return false
	}
	if p.Outcome != reconcile.EffectApplied {
		return p.Digest == ([32]byte{}) && len(p.Holders) == 0
	}
	if p.Digest == ([32]byte{}) || len(p.Holders) == 0 || len(p.Holders) > 64 || p.ProviderRevision != w.Request.ExpectedProviderRevision+1 {
		return false
	}
	reporter := false
	for i, h := range p.Holders {
		if i > 0 && slices.Compare(p.Holders[i-1].Voter[:], h.Voter[:]) >= 0 {
			return false
		}
		if !ed25519.Verify(ed25519.PublicKey(h.Voter[:]), HolderBytes(p, h.Voter), h.Signature) {
			return false
		}
		reporter = reporter || h.Voter == p.Reporter
	}
	return reporter
}

// maxBuiltinHoldings bounds the published builtin revisions one tree keeps.
const maxBuiltinHoldings = 2 * maxObjects

// BuiltinHolding is the Raft record of one published builtin revision: the
// digest of its sealed value and the voters that hold it. The value itself
// stays in those voters' local stores.
type BuiltinHolding struct {
	Kind     WriteKind
	Object   string
	Revision uint64
	Digest   [32]byte
	Holders  [][32]byte
}

func (h BuiltinHolding) key() string {
	return string(h.Kind) + "/" + h.Object + "/" + strconv.FormatUint(h.Revision, 10)
}
func (h BuiltinHolding) own() BuiltinHolding { h.Holders = slices.Clone(h.Holders); return h }
func (h BuiltinHolding) valid() bool {
	if h.Kind != ValueWrite && h.Kind != VerifierWrite || !cleanText(h.Object) || h.Revision == 0 || h.Revision >= 1<<31 || h.Digest == ([32]byte{}) || len(h.Holders) == 0 || len(h.Holders) > 64 {
		return false
	}
	for i, v := range h.Holders {
		if v == ([32]byte{}) || i > 0 && slices.Compare(h.Holders[i-1][:], v[:]) >= 0 {
			return false
		}
	}
	return true
}

// BuiltinHolding returns the holding of a published builtin revision.
func (t Tree) BuiltinHolding(kind WriteKind, object string, revision uint64) (BuiltinHolding, bool) {
	h, ok := t.builtin[BuiltinHolding{Kind: kind, Object: object, Revision: revision}.key()]
	return h.own(), ok
}

// DefaultProfile is the profile used when none is named: the one enabled
// installed profile of that kind, the builtin profile when there is none,
// and "" when there are several (the caller must name one).
func (t Tree) DefaultProfile(kind WriteKind) string {
	found := []string{}
	for id, p := range t.profiles {
		if p.Enabled && (kind == ValueWrite && p.Values || kind == VerifierWrite && p.Verifiers) {
			found = append(found, id)
		}
	}
	switch len(found) {
	case 0:
		return BuiltinProfile
	case 1:
		return found[0]
	}
	return ""
}

// BuiltinHoldings lists the tree's published builtin revisions.
func (t Tree) BuiltinHoldings() []BuiltinHolding {
	out := make([]BuiltinHolding, 0, len(t.builtin))
	for _, h := range t.builtin {
		out = append(out, h.own())
	}
	slices.SortFunc(out, func(a, b BuiltinHolding) int { return strings.Compare(a.key(), b.key()) })
	return out
}

// PruneBuiltin drops holdings nothing can read any more: a value revision
// that is neither its secret's current reference nor pinned by a retained
// usage, and a verifier that is not its group's current binding. It is
// derived bookkeeping, so the tree revision does not change.
func (t Tree) PruneBuiltin(a Approvals) Tree {
	keep := map[string]bool{}
	for _, o := range t.objects {
		if o.Status == Retired {
			continue
		}
		if o.Kind == Secret && o.Reference.Profile == BuiltinProfile && o.Reference.Revision != 0 {
			keep[BuiltinHolding{Kind: ValueWrite, Object: o.Reference.Object, Revision: o.Reference.Revision}.key()] = true
		}
		if b := o.VerifierBinding; b != nil && b.Reference.Profile == BuiltinProfile {
			keep[BuiltinHolding{Kind: VerifierWrite, Object: b.Reference.Object, Revision: b.Reference.Revision}.key()] = true
		}
	}
	if a.cluster == t.cluster {
		for _, u := range a.usages {
			if u.Grant.Realm != t.tenant {
				continue
			}
			for _, leaf := range u.Plan.Leaves {
				if leaf.Reference.Profile == BuiltinProfile {
					keep[BuiltinHolding{Kind: ValueWrite, Object: leaf.Reference.Object, Revision: leaf.Reference.Revision}.key()] = true
				}
			}
		}
	}
	drop := false
	for k := range t.builtin {
		drop = drop || !keep[k]
	}
	if !drop {
		return t
	}
	n := t
	n.builtin = map[string]BuiltinHolding{}
	for k, h := range t.builtin {
		if keep[k] {
			n.builtin[k] = h.own()
		}
	}
	return n
}

// AddBuiltinHolder records that voter now holds the published revision with
// digest d, and keeps only holders for which current is true. Like pruning,
// it leaves the tree revision unchanged.
func (t Tree) AddBuiltinHolder(kind WriteKind, object string, revision uint64, d [32]byte, voter [32]byte, current func([32]byte) bool) (Tree, error) {
	key := BuiltinHolding{Kind: kind, Object: object, Revision: revision}.key()
	h, ok := t.builtin[key]
	if !ok || h.Digest != d || voter == ([32]byte{}) || !current(voter) {
		return t, ErrPolicy
	}
	holders := [][32]byte{voter}
	for _, v := range h.Holders {
		if v != voter && current(v) {
			holders = append(holders, v)
		}
	}
	slices.SortFunc(holders, func(a, b [32]byte) int { return slices.Compare(a[:], b[:]) })
	if slices.Equal(holders, h.Holders) {
		return t, nil
	}
	h.Holders = holders
	if !h.valid() {
		return t, ErrPolicy
	}
	n := t
	n.builtin = map[string]BuiltinHolding{}
	for k, v := range t.builtin {
		n.builtin[k] = v.own()
	}
	n.builtin[key] = h
	return n, nil
}
