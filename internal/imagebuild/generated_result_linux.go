// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// The native seal is the completed effect. Reconstruct its SAME deterministic
// signing bytes without checking/creating files or persisting a new seal. A
// result is history, not a claim that bytes are currently available to publish.
func storedGeneratedFact(parent *bolt.Bucket, a GeneratedArtifact, original nativeGeneratedArchive, key ed25519.PrivateKey) (*SealReceipt, bool, bool, error) {
	if parent == nil {
		return nil, false, false, ErrStorage
	}
	bucket := parent.Bucket([]byte(scopeName(a.Scope)))
	if bucket == nil {
		return nil, false, false, nil
	}
	var h localUpload
	raw := bucket.Get(spoolHeader)
	if len(raw) > 16<<10 || json.Unmarshal(raw, &h) != nil || !generatedIdentity(h, original) || h.Invalid || h.Deleted && h.Deleting || h.Received > a.Scope.Parts() || h.Unpublished != nil && (!h.Unpublished.valid(h) || h.Unpublished.Artifact != a.Digest()) {
		return nil, false, false, ErrStorage
	}
	discarded := h.Deleting || h.Deleted || h.Unpublished != nil
	if h.Seal == nil {
		return nil, false, discarded, nil
	}
	if !signingKey(a.Scope, key) || len(h.Seal.Signature) != 0 || h.Received != a.Scope.Parts() {
		return nil, false, false, ErrStorage
	}
	fact := *h.Seal
	fact.Signature = ed25519.Sign(key, SealReceiptBytes(fact))
	if !fact.Valid(a.Scope) || a.Git != nil && fact.Tree != a.Git.Tree {
		return nil, false, false, ErrStorage
	}
	return &fact, h.Deleted, false, nil
}

func StoredDraftFreezeResult(db Transactions, plan DraftFreezePlan, key ed25519.PrivateKey) (DraftResponse, error) {
	out := DraftResponse{Schema: 1, Scope: plan.Scope, Code: "NOT_INITIALIZED"}
	if db == nil || plan.Validate() != nil {
		return DraftResponse{}, ErrInvalid
	}
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, plan.Scope.Root)
		binding, found, err := resolveDraftBinding(parent, plan.Scope)
		if err != nil || !found {
			return err
		}
		raw := parent.Bucket([]byte(binding.Namespace)).Get(freezeKey(plan))
		if raw == nil {
			return nil
		}
		var h nativeDraftFreeze
		if len(raw) > 16<<10 || json.Unmarshal(raw, &h) != nil || !h.valid() || h.Plan != plan {
			return ErrConflict
		}
		out.Code = "PENDING"
		_, retiring, err := readDraftRetirement(parent, binding)
		if err != nil {
			return err
		}
		if h.Removing || retiring {
			out.Code = "DISCARDED"
		}
		if h.Scope == nil {
			return nil
		}
		a := GeneratedArtifact{Scope: *h.Scope, Draft: &h.Plan}
		original := nativeGeneratedArchive{Scope: *h.Scope, Plan: plan.Digest(), Device: h.Device, Inode: h.Inode}
		fact, reclaimed, discarded, err := storedGeneratedFact(parent, a, original, key)
		if err != nil {
			return err
		}
		if fact == nil {
			if discarded {
				out.Code = "DISCARDED"
			}
			return nil
		}
		frozen := FrozenDraft{Schema: 1, Plan: plan, Scope: *h.Scope, Fact: *fact}
		frozen.Signature = ed25519.Sign(key, FrozenDraftBytes(frozen))
		if !frozen.Valid() {
			return ErrStorage
		}
		out.Code, out.Frozen, out.Reclaimed = "FROZEN", &frozen, reclaimed
		return nil
	})
	return out, err
}

func StoredGitSaveResult(db Transactions, plan GitSavePlan, key ed25519.PrivateKey) (GitSaveResponse, error) {
	out := GitSaveResponse{Schema: 1, Plan: plan.Digest(), Code: "NOT_INITIALIZED"}
	if db == nil || plan.Validate() != nil {
		return GitSaveResponse{}, ErrInvalid
	}
	h, found, err := readGitSave(db, plan)
	if err != nil || !found {
		return out, err
	}
	out.Code = "PENDING"
	if h.Retirement != nil && !h.Retirement.Transferred {
		out.Code = "DISCARDED"
	}
	if h.Scope == nil {
		return out, nil
	}
	err = db.View(func(tx *bolt.Tx) error {
		a := GeneratedArtifact{Scope: *h.Scope, Git: &h.Plan}
		original := nativeGeneratedArchive{Scope: *h.Scope, Plan: plan.Digest(), Device: h.Device, Inode: h.Inode}
		fact, reclaimed, discarded, err := storedGeneratedFact(draftParent(tx, plan.Root), a, original, key)
		if err != nil {
			return err
		}
		if fact == nil {
			if discarded {
				out.Code = "DISCARDED"
			}
			return nil
		}
		saved := SavedGit{Schema: 1, Plan: plan, Scope: *h.Scope, Fact: *fact}
		saved.Signature = ed25519.Sign(key, SavedGitBytes(saved))
		if !saved.Valid() {
			return ErrStorage
		}
		out.Code, out.Saved, out.Reclaimed = "SAVED", &saved, reclaimed
		return nil
	})
	return out, err
}
