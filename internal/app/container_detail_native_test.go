// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/moby/moby/client"
)

// Fault and rollback affect only this fixture's exact original container.
// Restore the actual pre-test Resources even if either SDK reply is lost.
func verifyContainerDetailDrift(t *testing.T, ctx context.Context, r *Runtime, user userauth.Client, peer mydcp.Peer, session access.Session) {
	t.Helper()
	query := containerops.Query{Schema: 1, Kind: "inspect", Selection: containerops.Selection{App: "app", Service: "web"}, MaxBytes: containerops.MaxOutput, HistoryLimit: 1}
	reply, err := user.ObserveContainer(ctx, peer, session, "tenant", query)
	if err != nil || reply.Container == nil || reply.Container.Detail == nil {
		t.Fatal("initial real detail", err)
	}
	paged := query
	paged.MaxBytes = 128
	fragment, err := user.ObserveContainer(ctx, peer, session, "tenant", paged)
	if err != nil || fragment.Container == nil || fragment.Container.DetailPart == nil || fragment.Container.NextCursor == "" {
		t.Fatal("actual User/owner detail framing unavailable", err)
	}
	collected, err := user.InspectContainer(ctx, peer, session, "tenant", paged)
	if err != nil || collected.Container == nil || collected.Container.Detail == nil || collected.Container.DetailPart != nil || collected.Container.Detail.Name != reply.Container.Detail.Name {
		t.Fatal("actual snapshot client did not collect complete detail", err)
	}
	target := reply.Container.Target
	before, err := r.docker.API.ContainerInspect(ctx, target.NativeID, client.ContainerInspectOptions{})
	if err != nil || before.Container.HostConfig == nil {
		t.Fatal(err)
	}
	original := before.Container.HostConfig.Resources
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := r.docker.API.ContainerUpdate(clean, target.NativeID, client.ContainerUpdateOptions{Resources: &original}); err != nil {
			t.Error("restore exact owned container Resources", err)
			return
		}
		after, err := r.docker.API.ContainerInspect(clean, target.NativeID, client.ContainerInspectOptions{})
		if err != nil || after.Container.HostConfig == nil || after.Container.HostConfig.Memory != original.Memory || after.Container.HostConfig.NanoCPUs != original.NanoCPUs {
			t.Error("owned resource rollback baseline", err)
		}
	}()
	changed := original
	changed.Memory += 16 << 20
	if _, err = r.docker.API.ContainerUpdate(ctx, target.NativeID, client.ContainerUpdateOptions{Resources: &changed}); err != nil {
		t.Fatal("owned native drift injection", err)
	}
	reply, err = user.ObserveContainer(ctx, peer, session, "tenant", query)
	if err != nil || reply.Container == nil || reply.Container.Detail == nil {
		t.Fatal("detail rejected inequality it must display", err)
	}
	detail := reply.Container.Detail
	if !slices.Contains(detail.Drift, "memory") || detail.MemoryBytes != changed.Memory || reply.Container.Target.NativeID != target.NativeID {
		t.Fatal("actual memory drift/immutable target missing")
	}
	for _, field := range detail.Environment {
		if field.Source != "literal" && field.Value != nil {
			t.Fatal("actual image/native env value escaped")
		}
	}
}
