// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/secrets"
)

// VaultHolderReport is a voter's statement that it now stores the sealed
// value of one published builtin revision (it filled it in from a holder).
// The reducer adds the reporter to the holders and drops holders that are
// no longer voters. Only the digest is in it, never a value.
type VaultHolderReport struct {
	Schema              uint8
	Cluster, Reporter   [32]byte
	RootRevision, Epoch uint64
	At                  uint64
	Realm               string
	Kind                secrets.WriteKind
	Object              string
	Revision            uint64
	Digest              [32]byte
	Signature           []byte
}

func VaultHolderBytes(r VaultHolderReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-vault-holder-1\x00"), raw...)
}

func (r VaultHolderReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: VaultKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func (p Policy) vaultHolderReport(s state.State, cmd state.Command) (VaultHolderReport, error) {
	var r VaultHolderReport
	if cmd.Key != VaultKey || cmd.Kind != state.ModuleReport || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.RootRevision != s.Object(VaultKey).Revision || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Reporter[:], VaultHolderBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	current, pe := p.Current(s)
	if err != nil || want != cmd || pe != nil {
		return r, ErrCatalog
	}
	members, err := current.Members(s)
	if err != nil || !members.VoterKey(r.Reporter) {
		return r, ErrCatalog
	}
	return r, nil
}

func (p Policy) ResolveVaultHolderReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r VaultHolderReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, ErrCatalog
	}
	cmd, err := r.Command()
	if err == nil {
		_, err = p.vaultHolderReport(s, cmd)
	}
	return cmd, err
}

func (p Policy) reduceVaultHolder(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.vaultHolderReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	p, err = p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	members, err := p.Members(s)
	if err != nil {
		return nil, state.Invalid
	}
	v, err := p.Vault(s)
	if err != nil {
		return nil, state.Invalid
	}
	tree, ok := v.Trees[r.Realm]
	if !ok {
		return nil, state.ConditionFailed
	}
	tree, err = tree.AddBuiltinHolder(r.Kind, r.Object, r.Revision, r.Digest, r.Reporter, members.VoterKey)
	if err != nil {
		// The revision was pruned or replaced since the voter read it.
		return nil, state.ConditionFailed
	}
	v.Trees[r.Realm] = tree
	return p.vaultCheckpoint(s, v)
}
