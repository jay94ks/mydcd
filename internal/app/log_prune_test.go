// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/moby/moby/api/types/events"

	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/logstore"
	"github.com/jay94ks/seafield/tests/enginefake"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// A destroyed container's log is marked gone (by the event, or by a rescan
// for events missed), kept for logs.keep, then pruned; a live one stays.
func TestStoredLogsOfGoneContainers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "lp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	fake, err := enginefake.Start(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	dc, err := engine.Open(ctx, fake.Endpoint(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer dc.API.Close()
	store, err := logstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{logs: store, docker: dc}
	fake.AddImage(dockerspec.DockerOCIImage{}, "registry.test/x:1")
	ids := map[string]string{}
	for _, name := range []string{"live", "destroyed", "missed"} {
		c, err := dc.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: name, Config: &container.Config{Image: "registry.test/x:1"}})
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = c.ID
		if _, err := store.Append(c.ID, logstore.Meta{Name: name}, []logstore.Record{{Seq: 1, Time: time.Now(), Data: []byte("x")}}); err != nil {
			t.Fatal(err)
		}
	}
	h := r.engineLogHandler()
	for _, name := range []string{"destroyed", "missed"} {
		if _, err := dc.API.ContainerRemove(ctx, ids[name], client.ContainerRemoveOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ev := events.Message{Type: events.ContainerEventType, Action: events.ActionDestroy, Actor: events.Actor{ID: ids["destroyed"]}}
	if !h.Wants(ev) {
		t.Fatal("destroy not wanted")
	}
	if err := h.Handle(ctx, engineevents.Record{Event: ev}); err != nil {
		t.Fatal(err)
	}
	if in, _ := store.Info(ids["destroyed"]); in.Gone.IsZero() {
		t.Fatal("destroy did not mark gone")
	}
	if in, _ := store.Info(ids["missed"]); !in.Gone.IsZero() {
		t.Fatal("missed marked early")
	}
	if err := r.markGoneLogs(ctx); err != nil {
		t.Fatal(err)
	}
	for name, gone := range map[string]bool{"live": false, "destroyed": true, "missed": true} {
		if in, _ := store.Info(ids[name]); in.Gone.IsZero() == gone {
			t.Fatal(name, "gone", in.Gone)
		}
	}

	// Default keep (7d): nothing yet. keep "forever": nothing either.
	r.pruneLogs()
	r.logsPolicy = config.Logs{Keep: "forever"}
	r.pruneLogs()
	if all, _ := store.List(); len(all) != 3 {
		t.Fatal("pruned early", len(all))
	}
	// A tiny keep: both gone logs go, the live one stays.
	r.logsPolicy = config.Logs{Keep: "1ns"}
	r.pruneLogs()
	all, _ := store.List()
	if len(all) != 1 || all[0].Container != ids["live"] {
		t.Fatal("prune", all)
	}
}
