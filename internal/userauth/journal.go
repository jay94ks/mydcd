// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

const operationLimit = 256

var ErrOperationMissing = errors.New("original management intent not found")

// OperationRecord is private recovery state. Result records a confirmed past
// reply; it never authorizes another effect or substitutes for a current read.
type OperationRecord struct {
	Schema    uint8
	Profile   [32]byte
	User      string
	Operation control.UserOperation
	Result    *state.Result `json:",omitempty"`
}

func (OperationRecord) MarshalJSON() ([]byte, error) { return nil, ErrPrivateState }
func (OperationRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted management intent]")
}

// The private writer needs its explicit serialization boundary, never ordinary
// logging of OperationRecord. Keep the existing file/schema writer unchanged.
type operationRecord OperationRecord

func operationName(id string) string {
	digest := sha256.Sum256([]byte(id))
	return hex.EncodeToString(digest[:]) + ".json"
}

func operationRoot(home string, c Client, user string, create bool) (*os.Root, error) {
	if !safeID(user) {
		return nil, ErrPrivateState
	}
	r, err := profileRootID(home, c.Cluster, c.JournalProfile(), create)
	if err != nil {
		if !create && errors.Is(err, os.ErrNotExist) {
			return nil, ErrOperationMissing
		}
		return nil, err
	}
	for _, name := range []string{"operations", user} {
		if !create {
			if _, err := r.Lstat(name); os.IsNotExist(err) {
				_ = r.Close()
				return nil, ErrOperationMissing
			}
		}
		next, err := descend(r, name, create)
		_ = r.Close()
		if err != nil {
			return nil, err
		}
		r = next
	}
	return r, nil
}

func readOperation(root *os.Root, c Client, current access.Session, id string) (OperationRecord, error) {
	var record operationRecord
	if id == "" || readPrivate(root, operationName(id), &record) != nil || record.Schema != 1 || record.Profile != c.JournalProfile() || record.User != current.User || record.Operation.Session.User != current.User || record.Operation.RequestID != id || record.Operation.SelfLogout() || record.Operation.VerifyOriginal(c.Cluster) != nil {
		return OperationRecord{}, ErrPrivateState
	}
	if record.Result != nil && !settledManagementResult(*record.Result) {
		return OperationRecord{}, ErrPrivateState
	}
	return OperationRecord(record), nil
}

func sameOperation(a, b control.UserOperation) bool {
	return bytes.Equal(control.OperationBytes(a), control.OperationBytes(b)) && bytes.Equal(a.Signature, b.Signature)
}
func settledManagementResult(result state.Result) bool {
	return result.Index != 0 && result.ValidReason() && result.Code != state.Expired && result.Code != state.LedgerFull
}

func LoadOperation(home string, c Client, current access.Session, id string) (OperationRecord, error) {
	if c.Verify(current) != nil || id == "" {
		return OperationRecord{}, ErrPrivateState
	}
	r, err := operationRoot(home, c, current.User, false)
	if err != nil {
		return OperationRecord{}, err
	}
	defer r.Close()
	if _, err = r.Lstat(operationName(id)); os.IsNotExist(err) {
		return OperationRecord{}, ErrOperationMissing
	}
	return readOperation(r, c, current, id)
}

// StageOperation publishes one immutable original before any possible send.
// An existing ID cannot be rebound to another session/body/signature/CAS.
func StageOperation(home string, c Client, op control.UserOperation) (OperationRecord, error) {
	if c.Self == nil || c.Verify(op.Session) != nil || op.Session.Key != c.Self.Public || op.VerifyOriginal(c.Cluster) != nil || op.SelfLogout() {
		return OperationRecord{}, ErrPrivateState
	}
	r, err := operationRoot(home, c, op.Session.User, true)
	if err != nil {
		return OperationRecord{}, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return OperationRecord{}, err
	}
	defer unlock()
	if _, err = r.Lstat(operationName(op.RequestID)); err == nil {
		existing, err := readOperation(r, c, op.Session, op.RequestID)
		if err != nil || !sameOperation(existing.Operation, op) {
			return OperationRecord{}, ErrPrivateState
		}
		return existing, nil
	} else if !os.IsNotExist(err) {
		return OperationRecord{}, ErrPrivateState
	}
	dir, err := r.Open(".")
	if err != nil {
		return OperationRecord{}, ErrPrivateState
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return OperationRecord{}, ErrPrivateState
	}
	count := 0
	for _, name := range names {
		if len(name) == 69 && name[len(name)-5:] == ".json" {
			count++
		}
	}
	command, err := op.Command()
	if err != nil {
		return OperationRecord{}, ErrPrivateState
	}
	if count >= operationLimit && (count > operationLimit || command.Kind != state.ModuleWindow) {
		return OperationRecord{}, ErrPrivateState
	}
	record := OperationRecord{Schema: 1, Profile: c.JournalProfile(), User: op.Session.User, Operation: op}
	if err = writePrivate(r, operationName(op.RequestID), operationRecord(record)); err != nil {
		return OperationRecord{}, err
	}
	return record, nil
}

func RecordOperationResult(home string, c Client, current access.Session, op control.UserOperation, result state.Result) error {
	if c.Verify(current) != nil || !settledManagementResult(result) {
		return ErrPrivateState
	}
	r, err := operationRoot(home, c, current.User, false)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := readOperation(r, c, current, op.RequestID)
	if err != nil || !sameOperation(record.Operation, op) {
		return ErrPrivateState
	}
	if record.Result != nil {
		if *record.Result == result {
			return nil
		}
		return ErrPrivateState
	}
	record.Result = &result
	return writePrivate(r, operationName(op.RequestID), operationRecord(record))
}

// PruneOperations consumes an already quorum-confirmed module epoch. Callers
// must obtain it from the current authenticated API, never a CLI override.
func PruneOperations(home string, c Client, current access.Session, epoch uint64) (int, error) {
	if c.Verify(current) != nil || epoch < 2 {
		return 0, ErrPrivateState
	}
	r, err := operationRoot(home, c, current.User, false)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return 0, err
	}
	defer unlock()
	dir, err := r.Open(".")
	if err != nil {
		return 0, ErrPrivateState
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return 0, ErrPrivateState
	}
	var remove []string
	for _, name := range names {
		if len(name) != 69 || name[len(name)-5:] != ".json" {
			continue
		}
		var record operationRecord
		if readPrivate(r, name, &record) != nil {
			return 0, ErrPrivateState
		}
		verified, err := readOperation(r, c, current, record.Operation.RequestID)
		if err != nil || operationName(verified.Operation.RequestID) != name {
			return 0, ErrPrivateState
		}
		if verified.Result != nil && verified.Operation.Epoch < epoch {
			remove = append(remove, name)
		}
	}
	removed := 0
	for _, name := range remove {
		if err = r.Remove(name); err != nil {
			_ = dir.Sync()
			return removed, ErrPrivateState
		}
		removed++
	}
	if err = dir.Sync(); err != nil {
		return removed, ErrPrivateState
	}
	return removed, nil
}
