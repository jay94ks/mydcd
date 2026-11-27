// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"time"
)

func init() {
	defineNodeRead((*Runtime).nodeReadVaultApprovalPermit, true, "vault-approval-permit", "vault-approval-result")
	defineNodeRead((*Runtime).nodeReadVaultWritePermit, true, "vault-write-permit")
}

func (r *Runtime) nodeReadVaultApprovalPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, errors.New("managed quorum approval read required")
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	if method == "vault-approval-result" {
		command, err := state.DecodeCommand(input)
		if err != nil {
			return nil, err
		}
		result, err := r.controlPolicy.VaultApprovalResult(v.State, caller, command)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	q, err := schema.Decode[control.VaultApprovalPermitRequest](input)
	now := time.Now().Unix()
	if err != nil || !access.Recent(q.At, now, 30) {
		return nil, errors.New("stale approval permit")
	}
	permit, err := r.controlPolicy.VaultApprovalPermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadVaultWritePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, errors.New("managed quorum Vault read required")
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.VaultWritePermitRequest](input)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if !access.Recent(q.At, now, 30) {
		return nil, errors.New("stale Vault permit request")
	}
	permit, err := r.controlPolicy.VaultWritePermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}
