// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// This is the actual SDK/private-sync boundary, with injected authorization.
// It deliberately constructs no fake checker observation or Raft/user success.
func exerciseRequestedContainerControl(t *testing.T, ctx context.Context, manager *workload.Manager, key, root string, node [32]byte) {
	t.Helper()
	before, err := manager.Status(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	record, err := manager.View(key)
	if err != nil {
		t.Fatal(err)
	}
	request := sha256.Sum256([]byte("admitted-user-request-adapter-fixture"))
	boot := sha256.Sum256([]byte("fixture-owner-boot"))
	target := contract.Target{Service: "web", TaskKey: key, NativeID: before.NativeID, Owner: hex.EncodeToString(node[:]), OwnerBoot: hex.EncodeToString(boot[:]), Generation: record.State.Applied.Generation, Revision: record.State.Desired.Revision, StartedAt: before.StartedAt}
	control, err := checker.NewRequestedContainerControl(hex.EncodeToString(request[:]), request, target, checker.RestartContainer)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(root, "requested-control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	save := func(next checker.ContainerControl) error {
		raw, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err = db.Write(map[string][]byte{"original": raw}); err != nil {
			return err
		}
		control = next
		return nil
	}
	if err = save(control); err != nil {
		t.Fatal(err)
	}
	failedSync := errors.New("requested control marker not synced")
	if err = manager.ControlContainerAction(ctx, control, true, func(checker.ContainerControl) error { return failedSync }, func(context.Context) error { return nil }); !errors.Is(err, failedSync) {
		t.Fatal("SDK dispatched before original user receipt sync", err)
	}
	unchanged, err := manager.Status(ctx, key)
	if err != nil || unchanged.NativeID != before.NativeID || unchanged.StartedAt != before.StartedAt {
		t.Fatal("failed sync changed original process", err)
	}
	for {
		err = manager.ControlContainerAction(ctx, control, true, save, func(context.Context) error { return nil })
		if err == nil {
			break
		}
		if !errors.Is(err, reconcile.ErrPending) {
			t.Fatal("actual requested SDK restart", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	after, err := manager.Status(ctx, key)
	if err != nil || control.Phase != checker.ControlCompleted || after.NativeID != before.NativeID || after.StartedAt == before.StartedAt || !after.Running {
		t.Fatal("requested SDK control recreated native or failed to start", err)
	}
	if err = manager.ControlContainerAction(ctx, control, true, save, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	duplicate, err := manager.Status(ctx, key)
	if err != nil || duplicate.StartedAt != after.StartedAt {
		t.Fatal("terminal original request repeated SDK effect", err)
	}
}
