// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

const userExecPrefix = "user-exec/"
const maxUserExecRecords = 4096
const maxUserExecRecordBytes = 128 << 10

type userExecRecord struct {
	Schema   uint8
	Original access.Session
	Intent   containerops.SessionIntent
	Receipt  containerops.ExecReceipt
}

func userExecKey(i containerops.SessionIntent) string {
	return userExecPrefix + i.Target.Tenant + "/" + i.User + "/" + i.Target.App + "/" + i.Request
}

func (r *Runtime) validateUserExec(row userExecRecord) error {
	i := row.Intent
	if row.Schema != 1 || r.Identity == nil || i.Target.Owner != r.Identity.Public || i.Target.Cluster != r.controlPolicy.Cluster || access.VerifyOriginalSession(row.Original, i.Target.Cluster, i.At) != nil || i.Verify(row.Original.Key) != nil || i.Session != access.ExactSessionDigest(row.Original) || i.User != row.Original.User || i.Spec.Kind != "exec" || row.Receipt.Validate() != nil || row.Receipt.Intent != i.Digest() {
		return containerops.ErrSession
	}
	return nil
}

// Caller holds userExecMu. A sync/read failure poisons this runtime's writer;
// no native action uses a replacement record after ambiguous persistence.
func (r *Runtime) loadUserExec(i containerops.SessionIntent) (userExecRecord, error) {
	var row userExecRecord
	if r.reports == nil || r.userExecStoreFailed {
		return row, containerops.ErrSession
	}
	raw, err := r.reports.GetBounded(userExecKey(i), maxUserExecRecordBytes)
	if err != nil {
		return row, err
	}
	row, err = schema.Decode[userExecRecord](raw)
	if err != nil || r.validateUserExec(row) != nil || row.Intent.Digest() != i.Digest() {
		return userExecRecord{}, containerops.ErrSession
	}
	return row, nil
}

func (r *Runtime) saveUserExec(row userExecRecord) error {
	if r.validateUserExec(row) != nil || r.reports == nil || r.userExecStoreFailed {
		return containerops.ErrSession
	}
	raw, err := json.Marshal(row)
	if err != nil || len(raw) > maxUserExecRecordBytes {
		return containerops.ErrSession
	}
	if err = r.reports.Write(map[string][]byte{userExecKey(row.Intent): raw}); err != nil {
		r.userExecStoreFailed = true
		return err
	}
	return nil
}

func (r *Runtime) reserveUserExec(original access.Session, intent containerops.SessionIntent, receipt containerops.ExecReceipt) (containerops.ExecReceipt, bool, error) {
	r.userExecMu.Lock()
	defer r.userExecMu.Unlock()
	row, err := r.loadUserExec(intent)
	if err == nil {
		return row.Receipt, false, nil
	}
	if !errors.Is(err, storage.ErrMissing) {
		return receipt, false, err
	}
	// Bound metadata independently of argv/output. No unresolved record is
	// silently evicted; a full owner store explicitly refuses a new exec.
	sizes, err := r.reports.SizesBounded(userExecPrefix, maxUserExecRecords, maxUserExecRecords*512)
	if err != nil || len(sizes) >= maxUserExecRecords {
		return receipt, false, containerops.ErrLimit
	}
	row = userExecRecord{Schema: 1, Original: original, Intent: intent, Receipt: receipt}
	if err = r.saveUserExec(row); err != nil {
		return receipt, false, err
	}
	return receipt, true, nil
}

func (r *Runtime) updateUserExec(intent containerops.SessionIntent, next containerops.ExecReceipt) error {
	r.userExecMu.Lock()
	defer r.userExecMu.Unlock()
	row, err := r.loadUserExec(intent)
	if err != nil {
		return err
	}
	next.StdinClosed = next.StdinClosed || row.Receipt.StdinClosed
	next.OutputEnded = next.OutputEnded || row.Receipt.OutputEnded
	next.Detached = next.Detached || row.Receipt.Detached
	if !next.CanFollow(row.Receipt) {
		// An Inspect response can race a later positive receipt. Retain the
		// newer fact rather than rewinding it or authorizing another start.
		if row.Receipt.CanFollow(next) {
			return nil
		}
		return containerops.ErrSession
	}
	row.Receipt = next
	return r.saveUserExec(row)
}

func (r *Runtime) userExecIOFacts(intent containerops.SessionIntent, stdin, output, detached bool) (containerops.ExecReceipt, error) {
	r.userExecMu.Lock()
	defer r.userExecMu.Unlock()
	row, err := r.loadUserExec(intent)
	if err != nil {
		return containerops.ExecReceipt{}, err
	}
	next := row.Receipt
	next.StdinClosed = next.StdinClosed || stdin
	next.OutputEnded = next.OutputEnded || output
	next.Detached = next.Detached || detached
	if !next.CanFollow(row.Receipt) {
		return row.Receipt, containerops.ErrSession
	}
	row.Receipt = next
	return next, r.saveUserExec(row)
}

func (r *Runtime) userExecRecord(intent containerops.SessionIntent) (userExecRecord, error) {
	r.userExecMu.Lock()
	defer r.userExecMu.Unlock()
	return r.loadUserExec(intent)
}
