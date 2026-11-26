// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/storage"
)

// IdentityPath is derived solely from the committed local root. Historical
// directories are retained for original resource signatures and sealed inputs;
// they are never an authentication fallback.
func IdentityPath(c config.Node, r Record) string {
	if len(r.Root.Keys) == 0 {
		return c.Node.IdentityDir
	}
	return filepath.Join(c.Node.IdentityDir, "rotations", r.Root.Keys[len(r.Root.Keys)-1].Proof.Operation)
}
func OwnerIdentityPath(c config.Node, r Record, key [32]byte) (string, bool) {
	if key == r.Root.OriginalKey() {
		return c.Node.IdentityDir, true
	}
	for _, row := range r.Root.Keys {
		if row.Proof.New == key {
			return filepath.Join(c.Node.IdentityDir, "rotations", row.Proof.Operation), true
		}
	}
	return "", false
}

// NativeOwnerPath leaves the original namespace untouched. Each replacement
// identity gets its own future recipes; no old source, unknown job or local
// ciphertext is rewritten into a new owner's authority.
func NativeOwnerPath(c config.Node, r Record, key [32]byte) string {
	if key == r.Root.OriginalKey() {
		return c.Node.StateDir
	}
	return filepath.Join(c.Node.StateDir, "native-owners", identityHex(key))
}
func identityHex(key [32]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range key {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&15]
	}
	return string(out)
}

// PrepareIdentityRotation is idempotent for the original operation. The key,
// certificate and dual-signed preparation receipt are durable before returning.
func PrepareIdentityRotation(c config.Node, operation string) (lifecycle.IdentityProof, error) {
	r, err := Read(c)
	if err != nil || !lifecycle.ValidID(operation) {
		return lifecycle.IdentityProof{}, ErrInstallation
	}
	db, err := storage.Open(filepath.Join(c.Node.StateDir, filename))
	if err != nil {
		return lifecycle.IdentityProof{}, err
	}
	defer db.Close()
	key := "rotation/" + operation
	if raw, e := db.Get(key); e == nil {
		var saved lifecycle.IdentityProof
		if json.Unmarshal(raw, &saved) != nil || !saved.Valid() || saved.Cluster != r.Root.Cluster || saved.Node != r.Root.Self.ID || saved.Operation != operation || saved.Old != r.Root.Self.Key {
			return saved, ErrInstallation
		}
		newIdentity, e := identity.Load(filepath.Join(c.Node.IdentityDir, "rotations", operation))
		if e != nil {
			return saved, e
		}
		defer clear(newIdentity.Private)
		if saved.New != newIdentity.Public {
			return saved, ErrInstallation
		}
		return saved, nil
	} else if !errors.Is(e, storage.ErrMissing) {
		return lifecycle.IdentityProof{}, e
	}
	old, err := identity.Load(IdentityPath(c, r))
	if err != nil {
		return lifecycle.IdentityProof{}, err
	}
	defer clear(old.Private)
	path := filepath.Join(c.Node.IdentityDir, "rotations", operation)
	var next *identity.Identity
	if _, err = os.Lstat(filepath.Join(path, "key.pem")); os.IsNotExist(err) {
		next, err = identity.Create(path)
	} else if err == nil {
		next, err = identity.Load(path)
	}
	if err != nil {
		return lifecycle.IdentityProof{}, err
	}
	defer clear(next.Private)
	prepared, _ := json.Marshal(struct {
		Cluster         [32]byte
		Node, Operation string
		Old, New        [32]byte
		Original        [32]byte
		OwnerPath       string
	}{r.Root.Cluster, r.Root.Self.ID, operation, old.Public, next.Public, r.Root.OriginalKey(), NativeOwnerPath(c, r, old.Public)})
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: r.Root.Cluster, Node: r.Root.Self.ID, Operation: operation, Old: old.Public, New: next.Public, Prepared: sha256.Sum256(prepared)}
	proof.OldSignature = ed25519.Sign(old.Private, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next.Private, lifecycle.IdentityProofBytes(proof))
	raw, _ := json.Marshal(proof)
	if err = db.Write(map[string][]byte{key: raw}); err != nil {
		return lifecycle.IdentityProof{}, err
	}
	return proof, syncDirectory(c.Node.StateDir)
}

// ActivateIdentityRotation changes the installation selector and Root in one
// durable database transaction. A crash before it resumes the old key; a crash
// after it opens only the new TLS key. Activation never deletes old material.
func ActivateIdentityRotation(c config.Node, proof lifecycle.IdentityProof, index uint64) (Record, error) {
	r, err := Read(c)
	if err != nil {
		return r, err
	}
	if r.Root.Self.Key == proof.New {
		if len(r.Root.Keys) == 0 || r.Root.Keys[len(r.Root.Keys)-1].Proof.Operation != proof.Operation {
			return r, ErrInstallation
		}
		return r, nil
	}
	db, err := storage.Open(filepath.Join(c.Node.StateDir, filename))
	if err != nil {
		return r, err
	}
	raw, err := db.Get("rotation/" + proof.Operation)
	_ = db.Close()
	want, _ := json.Marshal(proof)
	if err != nil || !bytes.Equal(raw, want) {
		return r, ErrInstallation
	}
	next, err := identity.Load(filepath.Join(c.Node.IdentityDir, "rotations", proof.Operation))
	if err != nil {
		return r, err
	}
	defer clear(next.Private)
	if next.Public != proof.New {
		return r, ErrInstallation
	}
	r.Root, err = r.Root.RotateIdentity(proof, index)
	if err != nil {
		return r, err
	}
	r.Signature = ed25519.Sign(next.Private, signingBytes(r))
	return r, write(c.Node.StateDir, r)
}
