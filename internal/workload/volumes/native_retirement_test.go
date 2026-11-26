// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestNativeOriginalCreationRetirementRequiresPositiveIdentity(t *testing.T) {
	for _, scenario := range []string{"late", "foreign"} {
		t.Run(scenario, func(t *testing.T) {
			spec := nativeTestSpec(t)
			sdk := nativeSDK(t, spec)
			sdk.loseCreate = true
			sdk.forgetCreate = scenario == "late"
			path := filepath.Join(t.TempDir(), "native.db")
			m, err := OpenNative(path, sdk.client)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Close() }()
			key, err := m.Desired(spec, 1, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.Step(context.Background(), key); err == nil {
				t.Fatal("lost create reply claimed known")
			}
			if err = m.DeleteDesired(key, 2, 1); err != nil {
				t.Fatal(err)
			}
			if scenario == "foreign" {
				sdk.mu.Lock()
				sdk.value.Labels["org.mydc.spec"] = "foreign"
				sdk.mu.Unlock()
			}
			if err = m.Step(context.Background(), key); err == nil {
				t.Fatal("unobserved/foreign original create settled")
			}
			row, err := m.View(key)
			if err != nil || row.State.Pending == nil || row.State.Pending.ID != 1 || row.State.Pending.Phase != reconcile.Retiring || sdk.deleteCount() != 0 || sdk.createCount() != 1 {
				t.Fatal("lost original create or deleted unproven target", err)
			}
			if scenario == "foreign" {
				return
			}
			_ = m.Close()
			m, err = OpenNative(path, sdk.client)
			if err != nil {
				t.Fatal(err)
			}
			// Complete that SAME original SDK call; the product must not issue a
			// second Create or allocate another materialization to make it pass.
			sdk.mu.Lock()
			sdk.exists = true
			sdk.mu.Unlock()
			if err = m.Step(context.Background(), key); err != nil {
				t.Fatal("late original identity closure", err)
			}
			row, err = m.View(key)
			if err != nil || row.State.Pending != nil || row.State.Applied.Present || row.State.LastID != 1 || sdk.createCount() != 1 || sdk.deleteCount() != 1 {
				t.Fatal("retirement fabricated Apply/new ID", err)
			}
		})
	}
}
func TestNativePreparedDeleteDoesNotDispatchCreate(t *testing.T) {
	spec := nativeTestSpec(t)
	sdk := nativeSDK(t, spec)
	m, err := OpenNative(filepath.Join(t.TempDir(), "native.db"), sdk.client)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if absent, err := m.UnrecordedAbsent(context.Background(), spec, 1); err != nil || !absent {
		t.Fatal("never-submitted exact native observation", err)
	}
	key, err := m.Desired(spec, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = m.Step(ctx, key); err == nil {
		t.Fatal("cancelled context did not stop Prepared dispatch")
	}
	row, err := m.View(key)
	if err != nil || row.State.Pending == nil || row.State.Pending.Phase != reconcile.Prepared {
		t.Fatal("missing original Prepared", err)
	}
	if _, err = m.UnrecordedAbsent(context.Background(), spec, 1); err == nil {
		t.Fatal("recorded original intent bypassed its retirement")
	}
	if err = m.DeleteDesired(key, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	row, err = m.View(key)
	if err != nil || row.State.Pending != nil || row.State.LastID != 1 || row.State.Applied.Present || sdk.createCount() != 0 || sdk.deleteCount() != 0 {
		t.Fatal("Prepared cleanup created/deleted a native object", err)
	}
}
