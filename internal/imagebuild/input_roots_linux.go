// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/nodestorage"
	bolt "go.etcd.io/bbolt"
)

type InputRootOwner struct {
	Tenant   string
	Required bool // original native allocation requires its lease until closure
	Pending  bool // original Return acknowledgement is not durably settled
}

func StoredInputRoots(db Transactions) ([]nodestorage.Reference, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	var roots []nodestorage.Reference
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(spoolBucket)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(key, raw []byte) error {
			if raw != nil {
				return ErrStorage
			}
			parent := bucket.Bucket(key)
			var identity struct {
				Root          nodestorage.Reference
				Device, Inode uint64
			}
			if parent == nil {
				return ErrStorage
			}
			raw = parent.Get([]byte("identity"))
			if len(raw) > 16<<10 || json.Unmarshal(raw, &identity) != nil || identity.Root.Validate() != nil || identity.Device == 0 || identity.Inode == 0 {
				return ErrStorage
			}
			digest := identity.Root.Digest()
			if string(key) != hex.EncodeToString(digest[:]) {
				return ErrStorage
			}
			roots = append(roots, identity.Root)
			return nil
		})
	})
	return roots, err
}

// StoredInputRootOwners classifies original consumers from native metadata,
// not from a current allow-list or a pathname. Returned data does not prove a
// lease is held: the caller must query the actual RootManager journal.
func StoredInputRootOwners(db Transactions, root nodestorage.Reference) (map[string]InputRootOwner, error) {
	if db == nil || root.Validate() != nil {
		return nil, ErrInvalid
	}
	owners := map[string]InputRootOwner{}
	add := func(consumer, tenant string, required bool) error {
		prior, found := owners[consumer]
		if found && prior.Tenant != tenant {
			return ErrStorage
		}
		owners[consumer] = InputRootOwner{Tenant: tenant, Required: required || prior.Required, Pending: prior.Pending}
		return nil
	}
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, root)
		if parent == nil {
			return nil
		}
		var identity struct {
			Root          nodestorage.Reference
			Device, Inode uint64
		}
		if raw := parent.Get([]byte("identity")); len(raw) > 16<<10 || json.Unmarshal(raw, &identity) != nil || identity.Root != root || identity.Device == 0 || identity.Inode == 0 {
			return ErrStorage
		}
		return parent.ForEach(func(key, raw []byte) error {
			switch {
			case raw != nil && strings.HasPrefix(string(key), "git-"):
				var save nativeGitSave
				if len(raw) > 16<<10 || json.Unmarshal(raw, &save) != nil || !save.valid() || save.Plan.Root != root || !bytes.Equal(key, gitSaveKey(save.Plan)) {
					return ErrStorage
				}
				consumer := GitRootConsumer(save.Plan)
				if err := add(consumer, save.Plan.Tenant, save.Retirement == nil || !save.Retirement.Root.Returning); err != nil {
					return err
				}
				owner := owners[consumer]
				owner.Pending = save.Retirement != nil && save.Retirement.Root.Returning && !save.Retirement.Root.Returned
				owners[consumer] = owner
				if save.Scope != nil {
					return add(ArtifactRootConsumer(*save.Scope), save.Scope.Tenant, false)
				}
			case raw == nil && strings.HasPrefix(string(key), "draft-"):
				bucket := parent.Bucket(key)
				var draft draftIdentity
				if bucket == nil {
					return ErrStorage
				}
				raw := bucket.Get([]byte("identity"))
				if len(raw) > 16<<10 || json.Unmarshal(raw, &draft) != nil || draft.Scope.Validate() != nil || draft.Scope.Root != root || !validDraftBinding(draftBinding{Data: draft.Scope.Data(), Namespace: string(key), Identity: draft}, draft.Scope) {
					return ErrStorage
				}
				binding := draftBinding{Data: draft.Scope.Data(), Namespace: string(key), Identity: draft}
				retirement, started, err := readDraftRetirement(parent, binding)
				if err != nil {
					return err
				}
				consumer := DraftRootConsumer(draft.Scope)
				if err := add(consumer, draft.Scope.Tenant, !started || !retirement.Root.Returning); err != nil {
					return err
				}
				owner := owners[consumer]
				owner.Pending = started && retirement.Root.Returning && !retirement.Root.Returned
				owners[consumer] = owner
				cursor := bucket.Cursor()
				for key, raw := cursor.Seek([]byte("freeze-")); key != nil && bytes.HasPrefix(key, []byte("freeze-")); key, raw = cursor.Next() {
					var freeze nativeDraftFreeze
					if len(raw) > 16<<10 || json.Unmarshal(raw, &freeze) != nil || !freeze.valid() || freeze.Plan.Scope.Data() != draft.Scope.Data() || !bytes.Equal(key, freezeKey(freeze.Plan)) {
						return ErrStorage
					}
					if freeze.Scope != nil {
						if err := add(ArtifactRootConsumer(*freeze.Scope), freeze.Scope.Tenant, false); err != nil {
							return err
						}
					}
				}
			case raw == nil && len(key) == 64:
				bucket := parent.Bucket(key)
				if bucket == nil {
					return ErrStorage
				}
				var upload localUpload
				if raw := bucket.Get(spoolHeader); len(raw) > 16<<10 || json.Unmarshal(raw, &upload) != nil || upload.Scope.Validate() != nil || upload.Scope.Root != root || string(key) != scopeName(upload.Scope) {
					return ErrStorage
				}
				consumer := ArtifactRootConsumer(upload.Scope)
				required := !upload.Deleted
				if upload.Unpublished != nil {
					if !upload.Unpublished.valid(upload) {
						return ErrStorage
					}
					required = upload.Unpublished.Borrowed && !upload.Unpublished.Returning
				}
				if err := add(consumer, upload.Scope.Tenant, required); err != nil {
					return err
				}
				if upload.Unpublished != nil {
					owner := owners[consumer]
					owner.Pending = !upload.Unpublished.Returned
					owners[consumer] = owner
				}
			}
			return nil
		})
	})
	return owners, err
}
