// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
)

// This is the original A2 EffectCheckpoint, not a second execution journal or
// retry operation. Volume Starts use the existing activation grant instead.
type containerStart struct {
	Schema uint8
	Native string
}

func validStartNative(id string) bool {
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == id && !bytes.Equal(raw, make([]byte, 32))
}

func (d *DockerDriver) startIdentity(op reconcile.Operation, native string) error {
	if !validStartNative(native) {
		return engine.ErrOwnership
	}
	if d.startCheckpoint == nil {
		return nil
	}
	c := d.startCheckpoint
	s, err := schema.Decode[containerStart](c.Data)
	// A later in-place Apply of the same container (only its extra network
	// attachments changed) keeps the original Start witness of its identity.
	sameStart := c.Operation == op.ID && c.Target == op.Target || c.Target.Generation == op.Target.Generation && c.Target != op.Target && TaskIdentityResource(c.Target) == TaskIdentityResource(op.Target)
	if err != nil || s.Schema != 1 || !validStartNative(s.Native) || s.Native != native || !sameStart {
		return engine.ErrOwnership
	}
	return nil
}

func (d *DockerDriver) dispatchStart(op reconcile.Operation, native string) error {
	if d.startCheckpoint != nil || d.saveStart == nil || d.startIdentity(op, native) != nil {
		return reconcile.ErrPending
	}
	raw, err := json.Marshal(containerStart{Schema: 1, Native: native})
	if err != nil {
		return err
	}
	if err = d.saveStart(raw); err != nil {
		return err
	}
	d.startCheckpoint = &reconcile.EffectCheckpoint{Operation: op.ID, Target: op.Target, Data: bytes.Clone(raw)}
	return nil
}

func (d *DockerDriver) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	local := *d
	local.saveStart = save
	return local.Execute(ctx, key, op)
}
