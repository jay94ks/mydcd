// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestRouteAdmissionAuthorityKeepsOneRequestFloorDeadlineAndFullPermission(t *testing.T) {
	ref, _ := routeOwnerRecordFixture(t)
	work := control.RouteWork{Schema: 1, Reference: ref, Epoch: 1, AppsRevision: 10, ResourcesRevision: 11, PrepareAllowed: true, MaxConsumers: 8}
	now := time.Unix(100, 0)
	original := routeAdmissionAuthority{work: work, minimum: 20, until: now.Add(5 * time.Second)}
	ctx := context.Background()
	if !original.allows(ctx, ref.Local.Owner, 20, work, now) {
		t.Fatal("same source request rejected")
	}
	newer := work
	newer.AppsRevision++
	newer.ResourcesRevision++
	if !original.allows(ctx, ref.Local.Owner, 21, newer, now) {
		t.Fatal("unrelated committed progress rejected")
	}
	if original.allows(ctx, ref.Local.Owner, 19, work, now) || original.allows(ctx, ref.Local.Owner, 20, work, original.until) || original.allows(ctx, [32]byte{99}, 20, work, now) || (routeAdmissionAuthority{}).allows(ctx, ref.Local.Owner, 20, work, now) {
		t.Fatal("foreign, expired, missing or regressed authority accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if original.allows(canceled, ref.Local.Owner, 20, work, now) {
		t.Fatal("canceled request admitted")
	}
	for _, mutate := range []func(*control.RouteWork){
		func(w *control.RouteWork) { w.Epoch++ },
		func(w *control.RouteWork) { w.PrepareAllowed = false },
		func(w *control.RouteWork) { w.Retiring = true },
		func(w *control.RouteWork) { w.Reference.Lifetime.Token++ },
		func(w *control.RouteWork) { w.Reference.Native.Spec[0]++ },
		func(w *control.RouteWork) { w.Peer.ID[0]++ },
		func(w *control.RouteWork) { w.MaxConsumers-- },
	} {
		raw, _ := json.Marshal(work)
		var changed control.RouteWork
		if err := json.Unmarshal(raw, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		if original.allows(ctx, ref.Local.Owner, 21, changed, now) {
			t.Fatal("changed original permission retained source authority")
		}
	}
	if original.minimum != 20 || !original.until.Equal(now.Add(5*time.Second)) || original.work.AppsRevision != 10 {
		t.Fatal("readback renewed original request authority")
	}
}
