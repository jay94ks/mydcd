// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/deployment"
)

// The signed mode is optional. Legacy accepted operations retain strict root
// and inventory CAS; reading an old journal never changes its mode or target.
func AppBeginCASAllowed(change Change) bool {
	var q AppBegin
	return change.Action == "begin-app" && canonical(change.Payload, &q) == nil &&
		q.Target != nil && *q.Target != ([32]byte{}) && validID(q.Tenant) && validID(q.App) &&
		validID(q.Deployment) && validID(q.Upload) && validID(q.Operation)
}

// AppCreateTarget binds expected=0 to the absence of one named app. This is
// not permission to replace an existing entry; the reducer checks absence.
func AppCreateTarget(cluster [32]byte, tenant, app, deploymentID string) [32]byte {
	if cluster == ([32]byte{}) || !validID(tenant) || !validID(app) || !validID(deploymentID) {
		return [32]byte{}
	}
	raw, _ := json.Marshal(struct {
		Cluster                 [32]byte
		Tenant, App, Deployment string
	}{cluster, tenant, app, deploymentID})
	return sha256.Sum256(append([]byte("sfc-app-create-target-1\x00"), raw...))
}

// A health refresh or unrelated upload is not an edit to the accepted app.
// The reducer still rechecks the frozen Blueprint, current sources, ownership,
// quota, permissions, pending work and every original lifetime/claim boundary.
func (entry appEntry) beginTarget() [32]byte {
	if entry.Standalone != nil {
		return entry.standaloneTarget()
	}
	if entry.Delivery != nil {
		return [32]byte{}
	}
	var target struct {
		Scope        deployment.AppScope
		Origin       [32]byte
		Down         *UserOperation
		Pending      *AppDeliverySync
		Active       *deployment.OperationSummary
		Quiescent    bool
		Retirement   string
		TaskRestarts []TaskRestartRecord `json:",omitempty"`
		LogClears    []AppLogClearRecord `json:",omitempty"`
	}
	target.Scope, target.Origin = entry.Inventory.Scope(), entry.downTarget()
	target.Down, target.Pending = entry.Down, entry.PendingSync
	target.Quiescent = entry.Inventory.Quiescent()
	target.TaskRestarts, target.LogClears = entry.TaskRestarts, entry.LogClears
	if active, ok := entry.Inventory.Active(); ok {
		active.CompletedAt = 0
		target.Active = &active
	}
	if retirement, ok := entry.Inventory.Retirement(); ok {
		target.Retirement = retirement.ID
	}
	raw, err := json.Marshal(target)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(append([]byte("sfc-app-begin-target-1\x00"), raw...))
}
