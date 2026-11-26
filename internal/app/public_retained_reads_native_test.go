// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/client"
)

// Delay the original SDK readback, not a product result or deletion proof. The
// public reader must show deleting until that same owner publishes native Gone.
func verifyNativeRetainedSourceDeletion(t *testing.T, ctx context.Context, source *Runtime, root string, original volumes.NativeReady, job control.VolumeMove, p control.Policy, read func() cluster.View, wait func(string, func() bool), controls managedMoveNativeControls) {
	t.Helper()
	if controls.sourceUsage == nil {
		t.Fatal("original source SDK readback gate required")
	}
	assertRead := func(status string) {
		t.Helper()
		nativeRetainedSource(t, nativeVolumeShow(t, ctx, root, job.Binding.Scope), job.Binding.ID, job.Binding.Source.Node, status)
	}
	assertRead("retained")
	direct, err := engine.Open(ctx, "unix:///var/run/docker.sock", source.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	inspections := 0
	entered, release := controls.sourceUsage.armWhen(original.Owner.Native, func() bool {
		inspections++
		return inspections == 2
	})
	defer release()
	selection := job.Selection()
	request := "rq10-delete-original-retained"
	deleteRetainedMoveThroughCLI(t, ctx, root, selection, request)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original retained deletion SDK readback", ctx.Err())
	}
	if _, err := direct.API.VolumeInspect(ctx, original.Owner.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("expected actual original native Remove before readback", err)
	}
	assertRead("deleting")
	release()
	wait("original retained deletion signed Gone", func() bool {
		book, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		_, move, ok := book.Move(selection)
		return ok && move.SourceDeletion != nil && move.SourceDeletion.Gone != nil
	})
	assertRead("removed")
	deleteRetainedMoveThroughCLI(t, ctx, root, selection, request)
	t.Log("public retained source CLI uses original move ID/node: retained -> actual Remove with readback held/deleting -> same owner signed Gone/removed -> original deletion result replay")
}
