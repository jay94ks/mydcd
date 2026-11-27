// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// NativeReady is a node fact, not a Raft commit or permission to start a writer.
// Managed facts keep the inspected host path local. Fixed facts bind the
// explicit administrator-registered path; apps still receive only a name/ref.
type NativeReady struct {
	Schema     uint8
	Spec       NativeSpec
	Generation uint64
	Owner      Owner
	Signature  []byte
	Fixed      *nodestorage.FixedDirectory `json:",omitempty"`
}

// NativeBindingDigest is the existing full signed-fact fingerprint, including
// fixed directory identity when present. It neither grants a read nor a Start.
func NativeBindingDigest(ready NativeReady) [32]byte {
	raw, _ := json.Marshal(ready)
	return sha256.Sum256(raw)
}

func NativeReadyBytes(r NativeReady) []byte {
	r.Signature = nil
	return signedBytes("sfc-volume-native-ready-1", r)
}
func (r NativeReady) Verify() error {
	raw, err := json.Marshal(r.Spec)
	if err != nil || r.Schema != 1 || r.Generation == 0 {
		return ErrNativeVolume
	}
	if r.Spec.Kind == "node-fixed" {
		if r.Spec.Validate() != nil || r.Fixed == nil || r.Fixed.Validate() != nil || r.Fixed.Root.Root.Cluster != r.Spec.Scope.Cluster || r.Fixed.Root.Root.Node != r.Spec.Node || r.Fixed.Root.Root.Key != r.Spec.NodeKey || r.Generation != r.Spec.Scope.Generation || r.Owner != (Owner{Node: r.Spec.Node, Key: r.Spec.NodeKey, Native: FixedNativeName(r.Spec.Scope)}) || !verify(r.Spec.NodeKey, NativeReadyBytes(r), r.Signature) {
			return ErrNativeVolume
		}
		// Selection is known before native discovery. This node signature
		// and the shared VolumeNativeDigest bind the FULL original directory.
		digest := r.Fixed.Selection().Digest()
		if r.Spec.FixedDigest != hex.EncodeToString(digest[:]) {
			return ErrNativeVolume
		}
		return nil
	}
	if r.Fixed != nil {
		return ErrNativeVolume
	}
	s, err := decodeNative(string(raw))
	if err != nil {
		return err
	}
	c := engine.Client{Owner: engine.Owner(s.Scope.Cluster, s.NodeKey)}
	id, err := c.Identity("volume", NativeKey(s), reconcile.Resource{Present: true, Generation: r.Generation, Spec: string(raw)})
	if err != nil || r.Owner != (Owner{Node: s.Node, Key: s.NodeKey, Native: id.Name}) || !verify(s.NodeKey, NativeReadyBytes(r), r.Signature) {
		return ErrNativeVolume
	}
	return nil
}
func (m *NativeManager) Ready(ctx context.Context, key string, private ed25519.PrivateKey) (NativeReady, error) {
	if fixedNativeKey(key) {
		if m.fixed == nil || len(private) != ed25519.PrivateKeySize || !private.Public().(ed25519.PublicKey).Equal(m.fixed.private.Public()) {
			return NativeReady{}, ErrNativeVolume
		}
		return m.fixed.Ready(ctx, key)
	}
	owner, scope, err := m.Owner(ctx, key)
	if err != nil {
		return NativeReady{}, err
	}
	r, err := m.journal.Read(key)
	if err != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource || r.State.Pending != nil {
		return NativeReady{}, ErrNativeVolume
	}
	s, _, err := m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: r.State.Applied})
	if err != nil || s.Scope != scope || len(private) != ed25519.PrivateKeySize || [32]byte(private.Public().(ed25519.PublicKey)) != owner.Key {
		return NativeReady{}, ErrNativeVolume
	}
	proof := NativeReady{Schema: 1, Spec: s, Generation: r.State.Applied.Generation, Owner: owner}
	proof.Signature = ed25519.Sign(private, NativeReadyBytes(proof))
	return proof, proof.Verify()
}

// CheckIdle proves the original native Volume is present without local users
// or Engine attachments. It grants no activation, opens no data and never
// returns a pin. An absent/unknown journal, pending operation or failed Engine
// query is not idle. The caller separately joins activation/Start ownership and
// revalidates current shared consumers before publishing its signed fact.
func (m *NativeManager) CheckIdle(ctx context.Context, ready NativeReady) error {
	if ready.Verify() != nil {
		return ErrNativeVolume
	}
	if ready.Fixed != nil {
		if m.fixed == nil {
			return ErrNativeVolume
		}
		return m.fixed.CheckIdle(ctx, ready)
	}
	key := NativeKey(ready.Spec)
	guard := m.declaration(key)
	guard.Lock()
	defer guard.Unlock()
	row, err := m.journal.Read(key)
	raw, marshalErr := json.Marshal(ready.Spec)
	if err != nil || marshalErr != nil || row.State.Pending != nil || !row.State.Applied.Present || row.State.Applied != row.State.Desired.Resource || row.State.Applied.Generation != ready.Generation || row.State.Applied.Spec != string(raw) || len(row.Consumers) != 0 {
		return errors.Join(ErrNativeVolume, err, marshalErr)
	}
	owner, scope, err := m.Owner(ctx, key)
	if err != nil || owner != ready.Owner || scope != ready.Spec.Scope {
		return errors.Join(ErrNativeVolume, err)
	}
	containers, err := m.driver.engine.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", ready.Owner.Native)})
	if err != nil || len(containers.Items) != 0 {
		return errors.Join(ErrNativeVolume, err)
	}
	return nil
}
