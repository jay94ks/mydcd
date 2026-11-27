// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func runStandaloneExtend(ctx context.Context, o standaloneOptions, tenant string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home string, out, diagnostic io.Writer) int {
	id := "standalone/extend/" + tenant + "/" + o.operation.value
	if old, err := userauth.LoadOperation(home, c, stored.Session, id); err == nil {
		var q control.StandaloneExtendChange
		if json.Unmarshal(old.Operation.Change.Payload, &q) != nil || old.Operation.Change.Action != "standalone-extend" || q.Tenant != tenant || q.Name != o.name.value || q.Operation != o.operation.value || q.TTLSeconds != o.ttl {
			return failure(diagnostic, errors.New("operation belongs to another original extension"), 2)
		}
		return standaloneMutation(ctx, c, peer, stored, home, id, old.Operation.Change.Action, old.Operation.Change.Expected, old.Operation.Epoch, q, out, diagnostic)
	} else if !errors.Is(err, userauth.ErrOperationMissing) {
		return failure(diagnostic, err, 2)
	}
	reply, err := c.StandalonePage(ctx, peer, stored.Session, tenant, o.name.value, "")
	if err != nil {
		return userFailure(diagnostic, err)
	}
	if len(reply.Standalones) != 1 || reply.Standalones[0].Target == ([32]byte{}) {
		return failure(diagnostic, errors.New("standalone management target unavailable"), 3)
	}
	v := reply.Standalones[0]
	if v.Metadata.Lifetime != "temp" || v.Metadata.Cleanup != nil || v.Metadata.Desired != "running" {
		return failure(diagnostic, errors.New("only an active temporary standalone can be extended"), 3)
	}
	q := control.StandaloneExtendChange{Tenant: tenant, Name: o.name.value, Scope: v.Metadata.Scope, Operation: o.operation.value, CreatedAt: v.Metadata.CreatedAt, PreviousExpiresAt: v.Metadata.ExpiresAt, TTLSeconds: o.ttl, Target: v.Target}
	return standaloneMutation(ctx, c, peer, stored, home, id, "standalone-extend", v.Metadata.Revision, max(reply.ModuleEpoch, 1), q, out, diagnostic)
}

func standaloneExtensionOutput(output map[string]any, op control.UserOperation, result *state.Result) {
	if op.Change.Action != "standalone-extend" || result == nil {
		return
	}
	plan, err := control.StandaloneExtensionResult(op)
	if errors.Is(err, access.ErrInvalid) {
		return
	}
	output["extension"] = plan
	output["extension_applied"] = result.Code == state.Applied
	if result.Code != state.Applied && err != nil {
		output["extension_code"] = err.Error()
	}
}
