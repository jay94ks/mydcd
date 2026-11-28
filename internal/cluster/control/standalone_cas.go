// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/deployment"
)

// StandaloneCASAllowed selects the standalone target mode from the signed
// change itself.
func StandaloneCASAllowed(change Change) bool {
	switch change.Action {
	case "standalone-up":
		var q AppBegin
		return canonical(change.Payload, &q) == nil && q.Standalone != nil &&
			q.Target != nil && *q.Target != ([32]byte{}) &&
			validID(q.Tenant) && validID(q.App) && validID(q.Deployment) &&
			validID(q.Upload) && validID(q.Operation) && validID(q.Standalone.Name)
	case "standalone-extend":
		var q StandaloneExtendChange
		return change.Expected > 0 && canonical(change.Payload, &q) == nil && q.valid()
	case "standalone-pin", "standalone-remove":
		var q StandaloneChange
		return change.Expected > 0 && canonical(change.Payload, &q) == nil &&
			q.Target != nil && *q.Target != ([32]byte{}) &&
			validID(q.Tenant) && validID(q.Name) && validID(q.Operation)
	}
	if standaloneControlAction(change.Action) != "" {
		var q TaskRestartChange
		return TaskRestartCASAllowed(change) && canonical(change.Payload, &q) == nil &&
			q.Standalone != "" && q.ManagementTarget != nil && *q.ManagementTarget != ([32]byte{})
	}
	return false
}

// standaloneTarget fixes accepted management intent, not observation progress.
// The original signed up fixes its accepted definition/upload and namespace.
// Pin/lifetime/restart policy, cleanup, down and newly accepted native controls
// change the target; connection sampling and native/report completion do not.
func (entry appEntry) standaloneTarget() [32]byte {
	if entry.Standalone == nil {
		return [32]byte{}
	}
	metadata := *entry.Standalone
	metadata.Connections, metadata.ConnectionAt, metadata.DisconnectedAt, metadata.Revision = 0, 0, 0, 0
	var controls [][32]byte
	for _, row := range entry.TaskRestarts {
		if row.Policy == nil {
			controls = append(controls, appRegistrationDigest(row.Origin))
		} else {
			controls = append(controls, sha256.Sum256(StandalonePolicyBytes(*row.Policy)))
		}
	}
	less := func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) }
	slices.SortFunc(controls, less)
	var down [32]byte
	if entry.Down != nil {
		down = appRegistrationDigest(*entry.Down)
	}
	raw, err := json.Marshal(struct {
		Scope    deployment.AppScope
		Origin   [32]byte
		Metadata StandaloneMetadata
		Down     [32]byte
		Controls [][32]byte
		// Clears is always nil since the log-clear recreate path was removed;
		// it stays so the target bytes of existing entries do not change.
		Clears [][32]byte
	}{entry.Inventory.Scope(), appRegistrationDigest(entry.Origin), metadata, down, controls, nil})
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(append([]byte("sfc-standalone-target-1\x00"), raw...))
}

func standaloneChangeMatches(entry appEntry, op UserOperation, q StandaloneChange) bool {
	if entry.Standalone == nil {
		return false
	}
	if !StandaloneCASAllowed(op.Change) {
		return q.Target == nil && op.Change.Expected == entry.Standalone.Revision
	}
	return StandaloneCASAllowed(op.Change) && op.Change.Expected <= entry.Standalone.Revision &&
		q.Target != nil && *q.Target == entry.standaloneTarget()
}
