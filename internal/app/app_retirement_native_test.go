// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/moby/moby/client"
)

func verifyAutomaticAppRetirement(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), request control.AppBindingRequest, nativeID string, withVolume bool, cliChecks ...func()) {
	t.Helper()
	r := *runtime
	a, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	i, _ := a.Inventory("tenant", "app")
	if len(cliChecks) == 3 {
		cliChecks[1]()
	} else {
		change("automatic-down", "down-app", i.Revision(), control.AppDown{Tenant: "tenant", App: "app", Operation: "stop-app"})
	}
	wait("daemon original retirement/whole reference release", func() bool {
		apps, e := p.Apps(read().State)
		if e != nil {
			t.Fatal(e)
		}
		for _, row := range apps.Records() {
			if row.App == "app" && row.Retirement != nil {
				return row.Retirement.ID == "stop-app" && row.Retirement.Status == "Retired"
			}
		}
		return false
	})
	if len(cliChecks) == 3 {
		cliChecks[2]()
		r = *runtime // a post-retirement consumer may reopen the same owner DB
	}
	a, err = p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	i, _ = a.Inventory("tenant", "app")
	if _, active := i.Execution(); active {
		t.Fatal("retired execution still active")
	}
	if _, bound := a.Binding(request.Task); bound {
		t.Fatal("retired Task binding remains live")
	}
	for _, claim := range i.Claims() {
		if claim.Step.Retain {
			if !claim.Retained || claim.Removed || claim.RetainProof == nil || !claim.RetainProof.Fenced {
				t.Fatal("retained writer not settled")
			}
			continue
		}
		if !claim.Removed || claim.Removal == nil || !claim.Removal.Delete.Command.Delete {
			t.Fatal("original removal chain missing", claim.Step.Kind)
		}
		if _, err := r.controlPolicy.AppResult(read().State, r.Identity.Public, claim.Removal.Delete.Command); err != nil {
			t.Fatal("late original removal result", err)
		}
		if read().State.Object(claim.Step.Key).Present {
			t.Fatal("retired shared source still live")
		}
	}
	if gone, err := r.docker.Gone(ctx, "container", request.Task.Key); err != nil || !gone {
		t.Fatal("actual Task remains", err)
	}
	if withVolume {
		registry, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		ready, ok := registry.Native("tenant", "app", "data")
		if !ok {
			t.Fatal("retained Volume registration lost")
		}
		volume, ok := registry.Volume(ready.Spec.Scope)
		if !ok || len(volume.Consumers()) != 0 {
			t.Fatal("shared writer not returned")
		}
		actual, err := r.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(actual.Volume.Mountpoint, "marker"))
		if err != nil || string(data) != "volume-original" {
			t.Fatal("retained data lost", err)
		}
	}
	// Input source removal is committed; both first metadata cleanup and a
	// repeated post-commit pass use that same proof, including after restart.
	for _, claim := range i.Claims() {
		if claim.Step.Kind == "inputs" && claim.Step.Owner == r.Identity.Public {
			ref, err := projectionClaimRef(claim)
			if err != nil {
				t.Fatal(err)
			}
			if err = r.projections.ForgetRetired(ref, a.Bindings(), i); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = r.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	*runtime = nil
	r, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	*runtime = r
	if _, err = r.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	a, err = p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range a.Records() {
		if row.App == "app" && (row.Retirement == nil || row.Retirement.Status != "Retired") {
			t.Fatal("retirement status lost in Snapshot/same DB")
		}
	}
	if gone, err := r.docker.Gone(ctx, "container", request.Task.Key); err != nil || !gone {
		t.Fatal("retired Task recreated", err)
	}
	t.Logf("original Task %s -> authenticated down CAS -> daemon original Drain/Proof/Delete -> real Secret/Volume whole release -> input/Bridge Gone -> retained writer/data -> finished retirement/Snapshot/same DB, no recreated Task", nativeID)
}
