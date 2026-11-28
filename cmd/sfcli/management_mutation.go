// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Mutation diagnostics use the durable original, not a fresh quorum read. This
// keeps the two CAS domains visible without re-signing or resubmitting anything.
func addMutationIdentity(output map[string]any, home string, c userauth.Client, stored userauth.Stored, id string) {
	output["request"] = id
	record, err := userauth.LoadOperation(home, c, stored.Session, id)
	if err != nil {
		output["journal_error"] = err.Error()
		return
	}
	op := record.Operation
	output["action"] = op.Change.Action
	output["epoch"] = op.Epoch
	output["root_revision"] = op.RootRevision
	output["expected_revision"] = op.Change.Expected
	if control.UploadCASAllowed(op.Change.Action) {
		output["cas"] = "upload"
	}
	if control.AppDownCASAllowed(op.Change) {
		output["cas"] = "app-down"
	}
	if control.AppFieldCASAllowed(op.Change) {
		output["cas"] = "app-field"
	}
	if control.StandaloneCASAllowed(op.Change) {
		output["cas"] = "standalone-target"
	}
	if control.AppLocalCASAllowed(op.Change) {
		output["cas"] = "app-local-target"
	}
	if control.AppBeginCASAllowed(op.Change) {
		output["cas"] = "app-begin-target"
	}
	if control.AppCDTargetCASAllowed(op.Change) {
		output["cas"] = "app-sync-target"
		if op.Change.Action == "configure-app-cd" {
			output["cas"] = "app-configure-target"
		}
	}
}

// managementMutation uses the existing signed operation journal. Only a newly
// staged original is sent automatically. Missing replies to an existing intent
// require explicit resume, retaining the original actor/epoch/ID/CAS/signature.
func managementMutation(ctx context.Context, c userauth.Client, target sfcp.Peer, stored userauth.Stored, home, id, action string, expected, epoch uint64, payload any, resume bool, before ...func(control.UserOperation) error) (*state.Result, error) {
	raw, err := control.ChangeBytes(action, stored.Session.User, expected, payload)
	if err != nil {
		return nil, err
	}
	var change control.Change
	if err = json.Unmarshal(raw, &change); err != nil {
		return nil, err
	}
	record, err := userauth.LoadOperation(home, c, stored.Session, id)
	fresh := errors.Is(err, userauth.ErrOperationMissing)
	if fresh {
		op, err := c.Prepare(ctx, target, stored.Session, id, change)
		if err != nil {
			return nil, err
		}
		if op.Epoch != epoch {
			return nil, errors.New("original management epoch changed; preserve intent without creating replacement mutations")
		}
		if action == "set-node-gateways" {
			raw, err = json.Marshal(op.Change)
			if err != nil {
				return nil, err
			}
		}
		record, err = userauth.StageOperation(home, c, op)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	original, _ := json.Marshal(record.Operation.Change)
	if !bytes.Equal(raw, original) || record.Operation.Epoch != epoch {
		return nil, errors.New("original management mutation does not match frozen intent")
	}
	if record.Result != nil {
		if resume && record.Result.Code == state.Applied && len(before) == 1 {
			if err := before[0](record.Operation); err != nil {
				return nil, err
			}
		}
		return record.Result, nil
	}
	var reply userauth.Reply
	if fresh {
		if len(before) == 1 {
			if err := before[0](record.Operation); err != nil {
				return nil, err
			}
		}
		reply, err = c.Operation(ctx, target, record.Operation, false)
	} else {
		checked := false
		reply, err = c.Result(ctx, target, stored.Session, record.Operation)
		if err == nil && (!reply.Found || reply.Result == nil) && resume {
			if len(before) == 1 {
				if err := before[0](record.Operation); err != nil {
					return nil, err
				}
				checked = true
			}
			reply, err = c.Resume(ctx, target, stored.Session, record.Operation)
		}
		if !checked && err == nil && reply.Result != nil && reply.Result.Code == state.Applied && resume && len(before) == 1 {
			if err := before[0](record.Operation); err != nil {
				return nil, err
			}
		}
	}
	if err != nil || !reply.Found || reply.Result == nil {
		return nil, errors.New("management outcome unknown; preserve original operation and use explicit resume")
	}
	if err = userauth.RecordOperationResult(home, c, stored.Session, record.Operation, *reply.Result); err != nil {
		return nil, err
	}
	return reply.Result, nil
}
