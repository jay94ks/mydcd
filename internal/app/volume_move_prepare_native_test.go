// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/client"
)

// One unavailable real SDK read must prevent full target preparation, even
// while its modules and original management network are present. It must not
// be confused with the separate missing-module negative fixture.
func armMoveNativeReadFailure(t *testing.T, ctx context.Context, source, target *Runtime, original volumes.NativeReady, job control.VolumeMove, p control.Policy, read func() cluster.View, wait func(string, func() bool), fault *managedCreateReplyFault) func() {
	t.Helper()
	if fault == nil || target.network == nil {
		t.Fatal("owned target SDK transport and full network Runtime required")
	}
	key := (tenancy.SourceIdentity{Kind: "bridge", Tenant: job.Binding.Scope.Tenant, Network: "move-target-network", Node: job.Binding.Target.Node}).Key()
	var native string
	wait("original target management native before injecting SDK read failure", func() bool {
		found, err := target.network.Inspect(ctx, key)
		if err != nil || found == "" {
			return false
		}
		native = found
		return true
	})
	row, err := target.network.View(key)
	if err != nil || !row.State.Applied.Present || row.State.Pending != nil {
		t.Fatal("original management native journal required", err)
	}
	physical, err := target.docker.Identity("bridge", key, row.State.Applied)
	if err != nil {
		t.Fatal(err)
	}
	taskKey := deployment.ResourceKey("task", job.Binding.Scope.Tenant, job.Binding.Scope.App, "web")
	before, err := source.workload.Status(ctx, taskKey)
	if err != nil || !before.Running || before.NativeID == "" {
		t.Fatal("actual original source Task must be running", err)
	}
	fault.failNetworkInspect(native, physical.Name)
	t.Cleanup(func() { fault.failNetworkInspect("", "") })
	return func() {
		t.Helper()
		if _, err := target.network.Inspect(ctx, key); err == nil || fault.networkReadFailures() == 0 {
			t.Fatal("owned target SDK inspection did not fail", err)
		}
		// Invoke the same serialized product preparation as the normal loop.
		// Its original empty native/intent may be reused; no replacement driver,
		// module removal, signed receipt or fallback Ready is introduced.
		if err := target.prepareMoveTarget(ctx, job); err == nil {
			t.Fatal("unavailable original target network produced full preparation")
		}
		registry, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		stored, move, found := registry.Move(job.Selection())
		core, haveCore := registry.Volume(job.Binding.Scope)
		owner, revision := core.Owner()
		if !found || !haveCore || stored.Digest() != job.Digest() || move.Phase != volumes.Prepared || move.Preparation != nil || move.Fence != nil || move.Manifest != nil || move.CommitRevision != 0 || owner != original.Owner || revision != job.Binding.SourceOwnerRevision {
			t.Fatal("failed target native read quiesced or replaced the original source")
		}
		apps, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		inventory, _ := apps.Inventory(job.Binding.Scope.Tenant, job.Binding.Scope.App)
		if _, retiring := inventory.Retirement(); retiring {
			t.Fatal("failed target preparation began original source retirement")
		}
		actual, err := source.docker.API.ContainerInspect(ctx, before.NativeID, client.ContainerInspectOptions{})
		if err != nil || actual.Container.State == nil || !actual.Container.State.Running {
			t.Fatal("actual source stopped before complete target preparation", err)
		}
		fault.failNetworkInspect("", "")
		t.Log("current target approval/full modules -> actual original Engine network Inspect unavailable -> same product prepare rejects/no source retirement or owner change -> original source remains Running -> release read failure and resume the same accepted move")
	}
}
