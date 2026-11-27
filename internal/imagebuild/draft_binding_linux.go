// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/nodestorage"
	bolt "go.etcd.io/bbolt"
)

// The index identifies the original namespace/inode; it does not duplicate
// editable state or grant authority.
type draftBinding struct {
	Data      DraftData
	Namespace string
	Identity  draftIdentity
}

func draftDataName(data DraftData) string {
	h := data.Digest()
	return "draft-" + hex.EncodeToString(h[:])
}
func draftIndexKey(data DraftData) []byte { return []byte("data-" + draftDataName(data)) }
func validDraftBinding(b draftBinding, scope DraftScope) bool {
	return b.Data == scope.Data() && b.Identity.Scope.Validate() == nil && b.Identity.Scope.Data() == b.Data && b.Identity.Device != 0 && b.Identity.Inode != 0 && b.Namespace == draftDataName(b.Data)
}
func draftParent(tx *bolt.Tx, root nodestorage.Reference) *bolt.Bucket {
	b := tx.Bucket(spoolBucket)
	if b != nil {
		h := root.Digest()
		b = b.Bucket([]byte(hex.EncodeToString(h[:])))
	}
	return b
}

func resolveDraftBinding(parent *bolt.Bucket, scope DraftScope) (draftBinding, bool, error) {
	if parent == nil {
		return draftBinding{}, false, nil
	}
	raw := parent.Get(draftIndexKey(scope.Data()))
	if raw == nil {
		return draftBinding{}, false, nil
	}
	var chosen draftBinding
	if len(raw) > 16<<10 || json.Unmarshal(raw, &chosen) != nil || !validDraftBinding(chosen, scope) {
		return chosen, false, ErrStorage
	}
	b := parent.Bucket([]byte(chosen.Namespace))
	var identity draftIdentity
	if b == nil || json.Unmarshal(b.Get([]byte("identity")), &identity) != nil || identity != chosen.Identity {
		return chosen, false, ErrStorage
	}
	return chosen, true, nil
}

// DraftStoredScope is a metadata-only lookup used to reopen the ORIGINAL
// RootManager consumer. A fresh request must not replace a missing old pin.
func DraftStoredScope(db Transactions, scope DraftScope) (DraftScope, bool, error) {
	if db == nil || scope.Validate() != nil {
		return DraftScope{}, false, ErrInvalid
	}
	var binding draftBinding
	var found bool
	err := db.View(func(tx *bolt.Tx) error {
		var err error
		binding, found, err = resolveDraftBinding(draftParent(tx, scope.Root), scope)
		return err
	})
	return binding.Identity.Scope, found, err
}

func saveDraftBinding(parent *bolt.Bucket, binding draftBinding) error {
	if parent == nil {
		return ErrStorage
	}
	key := draftIndexKey(binding.Data)
	raw, err := json.Marshal(binding)
	if err != nil {
		return ErrStorage
	}
	if old := parent.Get(key); old != nil {
		var previous draftBinding
		if json.Unmarshal(old, &previous) != nil || previous != binding {
			return ErrConflict
		}
		return nil
	}
	return parent.Put(key, raw)
}
