// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/vishvananda/netlink"
)

// Real read-only netlink boundary on an absent unique device; no privileged
// creation, route/firewall updates or cleanup mutation occurs in this test.
func TestTunnelReadOnlyInspectionDoesNotAttachOrCreateAbsentNative(t *testing.T) {
	spec := routeTunnelSpec(true)
	spec.Owner = "readonly-" + filepath.Base(t.TempDir())
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	driver := &TunnelDriver{Owner: spec.Owner}
	op := reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}}
	_, id, err := driver.parameters(t.Name(), op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkByName(id.name); !missingLink(err) {
		t.Fatal("refuse existing native", err)
	}
	if outcome, err := driver.Inspect(t.Context(), t.Name(), op); outcome == reconcile.EffectApplied || err == nil {
		t.Fatal("absent native became applied", outcome, err)
	}
	if _, err := netlink.LinkByName(id.name); !missingLink(err) || len(driver.files) != 0 {
		t.Fatal("inspection created/attached native", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := driver.Inspect(ctx, t.Name(), op); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	remove := op
	remove.Kind = reconcile.Remove
	if _, err := driver.Inspect(t.Context(), t.Name(), remove); !errors.Is(err, reconcile.ErrOperation) {
		t.Fatal("admission inspection accepted native removal", err)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Inspect(t.Context(), t.Name(), op); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
