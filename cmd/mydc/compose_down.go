// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func runComposeDown(ctx context.Context, o composeOptions, tenant, home string, c userauth.Client, target mydcp.Peer, stored userauth.Stored, out, diagnostic io.Writer) int {
	if o.retrySource.set {
		return failure(diagnostic, errors.New("retry-source requires original compose source preparation"), 2)
	}
	id := "compose-down/" + o.operation.value
	record, err := userauth.LoadOperation(home, c, stored.Session, id)
	var payload control.AppDown
	var expected, epoch uint64
	if errors.Is(err, userauth.ErrOperationMissing) && o.method == "down" {
		if _, old := userauth.LoadComposeSources(home, c, stored.Session, o.operation.value); old == nil {
			return failure(diagnostic, errors.New("operation ID already belongs to original compose source preparation"), 2)
		} else if !errors.Is(old, userauth.ErrOperationMissing) {
			return failure(diagnostic, old, 1)
		}
		if _, old := userauth.LoadCompose(home, c, stored.Session, o.operation.value); old == nil {
			return failure(diagnostic, errors.New("operation ID already belongs to an original up request"), 2)
		} else if !errors.Is(old, userauth.ErrOperationMissing) {
			return failure(diagnostic, old, 1)
		}
		current, found, err := composeInventory(ctx, c, target, stored, tenant, o.project.value)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		if !found {
			return failure(diagnostic, errors.New("app not found"), 1)
		}
		window, err := c.Query(ctx, target, stored.Session, "whoami", "")
		if err != nil {
			return userFailure(diagnostic, err)
		}
		payload = control.AppDown{Tenant: tenant, App: o.project.value, Operation: o.operation.value, Target: current.DownTarget}
		expected, epoch = current.Revision, max(1, window.ModuleEpoch)
	} else if err != nil {
		return failure(diagnostic, err, 1)
	} else {
		if record.Operation.Change.Action != "down-app" || json.Unmarshal(record.Operation.Change.Payload, &payload) != nil || payload.Operation != o.operation.value || payload.Tenant != tenant || o.project.set && payload.App != o.project.value {
			return failure(diagnostic, errors.New("original down request scope mismatch"), 2)
		}
		expected, epoch = record.Operation.Change.Expected, record.Operation.Epoch
	}
	if _, _, err := composeInventory(ctx, c, target, stored, tenant, payload.App); err != nil {
		return userFailure(diagnostic, err)
	}
	result, err := managementMutation(ctx, c, target, stored, home, id, "down-app", expected, epoch, payload, o.method == "resume")
	if err != nil || result == nil {
		if userOutput(out, diagnostic, map[string]any{"schema": 1, "operation": payload.Operation, "tenant": tenant, "app": payload.App, "request": id, "status": "unknown", "local_intent_preserved": true}) != 0 {
			return 1
		}
		return failure(diagnostic, errors.New("original down outcome unconfirmed; use explicit resume without replacing ID/CAS"), 4)
	}
	if result.Code != state.Applied {
		output := map[string]any{"schema": 1, "operation": payload.Operation, "request": id, "status": "rejected", "result": result, "local_intent_preserved": true}
		addMutationIdentity(output, home, c, stored, id)
		if userOutput(out, diagnostic, output) != 0 {
			return 1
		}
		return 3
	}
	current, found, err := composeInventory(ctx, c, target, stored, tenant, payload.App)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	if !found || current.Retirement == nil || current.Retirement.ID != payload.Operation {
		return failure(diagnostic, errors.New("original down receipt retained; current retirement is no longer this operation"), 4)
	}
	return userOutput(out, diagnostic, map[string]any{"schema": 1, "operation": payload.Operation, "tenant": tenant, "app": payload.App, "status": "retirement-accepted", "observed": current, "local_intent_preserved": true})
}
