// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// StoredDraftEditResult never opens/recreates a file, root pin or draft. A
// missing record is distinct from permission to execute the edit again.
func StoredDraftEditResult(db Transactions, scope DraftScope, edit DraftEdit) (DraftResponse, error) {
	out := DraftResponse{Schema: 1, Scope: scope, Code: "NOT_INITIALIZED"}
	if db == nil || scope.Validate() != nil || edit.Validate() != nil {
		return DraftResponse{}, ErrInvalid
	}
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, scope.Root)
		binding, found, err := resolveDraftBinding(parent, scope)
		if err != nil || !found {
			return err
		}
		raw := parent.Bucket([]byte(binding.Namespace)).Get([]byte("edit-" + edit.ID))
		if raw == nil {
			return nil
		}
		var record draftEditRecord
		if len(raw) > maxDraftEditRecordBytes || json.Unmarshal(raw, &record) != nil || !record.matches(edit) {
			return ErrConflict
		}
		if record.Result != nil {
			out.Code, out.Revision, out.Digest, out.Edit = "OK", record.Result.Revision, &record.Result.Draft, record.Result
			return nil
		}
		_, retiring, err := readDraftRetirement(parent, binding)
		if err != nil {
			return err
		}
		out.Code = "PENDING"
		if record.Abandoned || retiring {
			out.Code = "DISCARDED"
		}
		return nil
	})
	return out, err
}
