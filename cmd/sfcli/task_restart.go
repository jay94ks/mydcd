// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"io"
)

func runTaskRestart(ctx context.Context, o composeOptions, tenant string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home string, out, diagnostic io.Writer) int {
	q := control.TaskRestartQuery{Selection: containerops.Selection{App: o.project.value, Service: o.container.service, Instance: o.container.instance.value}}
	if o.method == "restart-status" {
		q.Selection.Service = ""
		q.Selection.Instance = ""
		q.Operation = o.operation.value
		reply, err := c.QueryTaskRestart(ctx, peer, stored.Session, tenant, false, q)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		return userOutput(out, diagnostic, reply.TaskRestartStatus)
	}
	id := "compose/restart/" + tenant + "/" + o.project.value + "/" + o.operation.value
	var payload control.TaskRestartChange
	var expected, epoch uint64
	if !o.logClearPreview.value {
		old, err := userauth.LoadOperation(home, c, stored.Session, id)
		if err == nil {
			if old.Operation.Change.Action != "restart-task" || json.Unmarshal(old.Operation.Change.Payload, &payload) != nil || payload.Tenant != tenant || payload.App != o.project.value || payload.Operation != o.operation.value || payload.Selection.Service != o.container.service || payload.Selection.Instance != o.container.instance.value {
				return failure(diagnostic, errors.New("restart ID belongs to a different original target; use its original status/result"), 2)
			}
			expected, epoch = old.Operation.Change.Expected, old.Operation.Epoch
		} else if !errors.Is(err, userauth.ErrOperationMissing) {
			return failure(diagnostic, err, 2)
		}
	}
	if epoch == 0 {
		reply, err := c.QueryTaskRestart(ctx, peer, stored.Session, tenant, true, q)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		plan := reply.TaskRestartPlan
		if o.logClearPreview.value {
			return userOutput(out, diagnostic, plan)
		}
		payload = control.TaskRestartChange{Tenant: tenant, App: o.project.value, Operation: o.operation.value, Target: plan.Target}
		payload.Selection.Service = o.container.service
		payload.Selection.Instance = o.container.instance.value
		expected, epoch = plan.InventoryRevision, max(reply.ModuleEpoch, 1)
	}
	result, err := managementMutation(ctx, c, peer, stored, home, id, "restart-task", expected, epoch, payload, false)
	response := map[string]any{"schema": 1, "operation": payload.Operation, "target": payload.Target, "status": "Unknown", "original_intent_preserved": true, "native_writable_layer_logs_preserved": true}
	addMutationIdentity(response, home, c, stored, id)
	code := 4
	if result != nil {
		response["result"] = result
		response["status"] = "Rejected"
		code = 3
		if result.Code == state.Applied {
			response["status"] = "Accepted"
			code = 0
			status, e := c.QueryTaskRestart(ctx, peer, stored.Session, tenant, false, control.TaskRestartQuery{Selection: containerops.Selection{App: o.project.value}, Operation: payload.Operation})
			if e == nil {
				response["execution"] = status.TaskRestartStatus
			}
		}
	}
	if userOutput(out, diagnostic, response) != 0 {
		return 1
	}
	if err != nil {
		return failure(diagnostic, err, 4)
	}
	return code
}
