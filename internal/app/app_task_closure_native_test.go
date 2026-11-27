// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload"
)

func verifyManagedAppTaskClosure(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, request control.AppBindingRequest, original reconcile.Resource) {
	t.Helper()
	spec, err := workload.DecodeContainer(original.Spec)
	if err != nil || spec.Inputs == nil {
		t.Fatal("original projection source", err)
	}
	if err = r.workload.Desired(request.Task.Key, request.Task.Revision+1, request.Task.Generation, nil, 8); err == nil {
		err = r.workload.Step(ctx, request.Task.Key)
	}
	if err != nil {
		t.Fatal("original revoked Task Remove", err)
	}
	stopped, proof, err := r.CollectAppTaskClosure(ctx, request)
	if err != nil || len(proof.Secrets) != 1 || len(proof.Volumes) != 1 || !stopped.Released || !stopped.Gone || stopped.Native == "" {
		t.Fatal("actual Task/Secret/Volume closure", err)
	}
	wrong := request
	wrong.Task.Generation++
	if _, _, e := r.CollectAppTaskClosure(ctx, wrong); e == nil {
		t.Fatal("other generation signed closure")
	}
	if _, _, err = r.CollectAppTaskClosure(ctx, request); err != nil {
		t.Fatal("original closure retry", err)
	}
	view := read()
	apps, err := p.Apps(view.State)
	if err != nil {
		t.Fatal(err)
	}
	var app control.AppView
	for _, entry := range apps.Records() {
		if entry.Tenant == "tenant" && entry.App == "app" {
			app = entry
		}
	}
	report := r.newAppProgress(view, app, "release-inputs", request.Task.Key, &stopped)
	report.Release = &control.AppBindingRelease{Digest: request.Digest, Proof: deployment.Closure{Secrets: proof.Secrets}}
	if err = r.sendAppProgress(ctx, report); err == nil {
		t.Fatal("Secret-only proof returned Volume usage")
	}
	view = read()
	apps, err = p.Apps(view.State)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := apps.Binding(request.Task); !ok {
		t.Fatal("partial proof lost original binding")
	}
	report = r.newAppProgress(view, app, "release-inputs", request.Task.Key, &stopped)
	report.Release = &control.AppBindingRelease{Digest: request.Digest, Proof: proof}
	if err = r.sendAppProgress(ctx, report); err != nil {
		t.Fatal("whole actual shared release", err)
	}
	apps, err = p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := apps.Binding(request.Task); ok {
		t.Fatal("original binding not released")
	}
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	ready, ok := registry.Native("tenant", "app", "data")
	if !ok {
		t.Fatal("retained Volume lost")
	}
	volume, ok := registry.Volume(ready.Spec.Scope)
	if !ok || len(volume.Consumers()) != 0 {
		t.Fatal("original writer consumer not returned")
	}
	if err = r.projections.Forget(*spec.Inputs, apps.Bindings()); err != nil {
		t.Fatal("private projection receipt not settled", err)
	}
	t.Log("real Vault/TLS/password approval -> original shared Binding -> private read-only projection + NoCopy Volume/nonroot Task -> seal/same DB/ID/health -> revoked activation -> original SDK Remove/Gone -> collector original Task signature + actual Secret/Volume closures -> partial proof denied/whole atomic release -> retained Volume and private receipt cleanup")
}
