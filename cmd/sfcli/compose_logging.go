// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func runLogClear(ctx context.Context, o composeOptions, tenant string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home string, out, diagnostic io.Writer) int {
	q := control.AppLogClearQuery{Selection: containerops.Selection{App: o.project.value, Service: o.container.service, Instance: o.container.instance.value}}
	action := "clear-app-logs"
	public := ""
	if o.standalone != nil {
		public = o.standalone.Name
		q.Selection = containerops.Selection{Standalone: public, Instance: o.container.instance.value}
		action = "standalone-clear-logs"
	}
	if o.method == "logs-clear-status" {
		q.Selection.Service, q.Selection.Instance, q.Operation = "", "", o.operation.value
		reply, err := c.QueryLogClear(ctx, peer, stored.Session, tenant, false, q)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		return userOutput(out, diagnostic, reply.LogClearStatus)
	}
	id := "compose/logs-clear/" + tenant + "/" + o.project.value + "/" + o.operation.value
	if public != "" {
		id = "standalone/logs-clear/" + tenant + "/" + o.project.value + "/" + o.operation.value
	}
	var payload control.AppLogClear
	var expected, epoch uint64
	// Resolve the original BEFORE planning today's native target. In particular
	// a retry must never delete a replacement container under the same ID.
	if o.logClearRecreate.value {
		old, err := userauth.LoadOperation(home, c, stored.Session, id)
		if err == nil {
			if old.Operation.Change.Action != action || json.Unmarshal(old.Operation.Change.Payload, &payload) != nil || payload.Tenant != tenant || (public == "" && payload.App != o.project.value || public != "" && payload.Standalone != public) || payload.Operation != o.operation.value || (public == "" && payload.Selection.Service != o.container.service) || payload.Selection.Instance != o.container.instance.value {
				return failure(diagnostic, errors.New("log-clear ID belongs to a different original target; use its original status/result"), 2)
			}
			expected, epoch = old.Operation.Change.Expected, old.Operation.Epoch
		} else if !errors.Is(err, userauth.ErrOperationMissing) {
			return failure(diagnostic, err, 2)
		}
	}
	if epoch == 0 {
		reply, err := c.QueryLogClear(ctx, peer, stored.Session, tenant, true, q)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		plan := reply.LogClearPlan
		if o.logClearPreview.value {
			return userOutput(out, diagnostic, map[string]any{"schema": 1, "plan": plan, "strategy": "recreate", "service_interruption": true, "writable_layer_and_local_logs_lost": true, "volume_data_preserved": true, "external_log_copies_excluded": true})
		}
		fmt.Fprintln(diagnostic, "Log clearing will stop/recreate the listed containers and dependents. Local logs and writable layers are irreversibly lost; Volume data and external log copies are preserved.")
		for _, impact := range plan.Impact {
			fmt.Fprintf(diagnostic, "  %s %s node=%s native=%s generation=%d retained=%t\n", impact.Kind, impact.Key, impact.Node, impact.NativeID, impact.Generation, impact.Retained)
		}
		payload = control.AppLogClear{Tenant: tenant, App: plan.App, Standalone: public, Operation: o.operation.value, Target: plan.Target, Recreate: true}
		payload.Selection.Service, payload.Selection.Instance = q.Selection.Service, o.container.instance.value
		expected, epoch = plan.InventoryRevision, max(reply.ModuleEpoch, 1)
	}
	result, err := managementMutation(ctx, c, peer, stored, home, id, action, expected, epoch, payload, false)
	response := map[string]any{"schema": 1, "operation": payload.Operation, "target": payload.Target, "status": "Unknown", "original_intent_preserved": true, "volume_data_preserved": true, "external_log_copies_excluded": true}
	addMutationIdentity(response, home, c, stored, id)
	code := 4
	if result != nil {
		response["result"], response["status"], code = result, "Rejected", 3
		if result.Code == state.Applied {
			response["status"], code = "Accepted", 0
			status, statusErr := c.QueryLogClear(ctx, peer, stored.Session, tenant, false, control.AppLogClearQuery{Selection: containerops.Selection{App: func() string {
				if public != "" {
					return ""
				}
				return o.project.value
			}(), Standalone: public}, Operation: payload.Operation})
			if statusErr == nil {
				response["execution"] = status.LogClearStatus
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
