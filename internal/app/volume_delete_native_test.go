// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func verifyVolumeDeleteBoundary(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, admin userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), source volumes.NativeReady, docker *engine.Client, gate *volumeUsageGate) {
	t.Helper()
	home := filepath.Join(root, "delete-client")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "delete-client.yaml")
	raw := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", admin.Cluster, a.Identity.Public, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	selectedTenant := ""
	cli := func(want int, args ...string) map[string]any {
		t.Helper()
		args = withTenant(selectedTenant, args)
		cmd := nativeCLICmd(ctx, os.Getenv("SFC_TEST_CLI"), home, profile, args...)
		var out, diagnostic bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostic
		err := cmd.Run()
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("volume CLI", args, code, diagnostic.String(), out.String())
		}
		var reply map[string]any
		if len(out.Bytes()) != 0 && json.Unmarshal(out.Bytes(), &reply) != nil {
			t.Fatal("CLI JSON")
		}
		return reply
	}
	registry := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	core := func() volumes.State {
		t.Helper()
		c, ok := registry().Volume(source.Spec.Scope)
		if !ok {
			t.Fatal("original volume tombstone missing")
		}
		return c
	}
	wait := func(label string, check func() bool) {
		t.Helper()
		for !check() {
			select {
			case <-ctx.Done():
				if *owner != nil {
					(*owner).mu.RLock()
					t.Log("volume controller", (*owner).volumeBackupError)
					(*owner).mu.RUnlock()
				}
				t.Fatal(label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	cli(0, "wallet", "init")
	cli(0, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	inspected := cli(0, "--tenant", "tenant", "volume", "show", "app/data")
	if inspected["Phase"] != "Ready" {
		t.Fatal("initial phase", inspected)
	}
	cli(1, "--tenant", "other", "volume", "show", "app/data")
	// A real shared pin denies deletion before SDK effects. This is not a
	// started workload; its owner-signed Release only closes this fixture pin.
	change("hold-volume", "acquire-volume", core().Revision(), control.VolumeAcquire{Scope: source.Spec.Scope, Consumer: "held", Generation: 1, Writable: true})
	held := core().Consumers()[0]
	cli(3, "--tenant", "tenant", "volume", "delete", "app/data", "--id", "busy-delete")
	closed := volumes.Gone{Scope: source.Spec.Scope, Consumer: held, Stopped: true, MountsGone: true}
	closed.Signature = ed25519.Sign((*owner).Identity.Private, volumes.GoneBytes(closed))
	change("return-held", "release-volume", core().Revision(), closed)
	key := volumes.NativeKey(source.Spec)
	pin, err := (*owner).nativeVolumes.Pin(ctx, key, "delete-native-pin", source.Generation)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if *owner != nil {
			_ = (*owner).nativeVolumes.Return(pin)
		}
	}()
	cli(0, "--tenant", "tenant", "volume", "delete", "app/data", "--id", "remove-data", "--no-wait")
	wait("exact native Drain with pin preserved", func() bool {
		r, err := (*owner).nativeVolumes.View(key)
		return err == nil && core().Deleting() && !r.State.Desired.Present && len(r.Consumers) == 1
	})
	if _, err := docker.API.VolumeInspect(ctx, source.Owner.Native, client.VolumeInspectOptions{}); err != nil {
		t.Fatal("native removed before pin return", err)
	}
	body, _ := json.Marshal(source.Spec.Scope)
	if _, err := a.appCall(ctx, "volume-delete-permit", body); err == nil {
		t.Fatal("another member impersonated native owner")
	}
	inspected = cli(0, "--tenant", "tenant", "volume", "show", "app/data")
	if inspected["Phase"] != "Deleting" {
		t.Fatal("accepted deletion reported as physical completion")
	}
	// Delay the SDK's post-Remove readback, not its response contents. Native
	// deletion has actually happened; restart must settle the original ID.
	inspections := 0
	entered, release := gate.armWhen(source.Owner.Native, func() bool { inspections++; return inspections == 2 })
	defer release()
	if err = (*owner).nativeVolumes.Return(pin); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("post-Remove observation gate", ctx.Err())
	}
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner = nil
	// Step holds the row mutex across I/O: inspect the durable original only
	// after Close has cancelled that worker and released the journal lock.
	journal, err := volumes.OpenNative(filepath.Join(cfg.Node.StateDir, "workload", "volumes.db"), docker)
	if err != nil {
		t.Fatal(err)
	}
	record, err := journal.View(key)
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || record.State.Pending == nil || record.State.Pending.Kind != reconcile.Remove {
		t.Fatal("original Remove lost", err)
	}
	originalRemove := record.State.Pending.ID
	release()
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wait("same owner DB settles original native Gone", func() bool { return core().Deleted() })
	proof, ok := core().Removal()
	if !ok || proof.Verify() != nil || proof.Owner != source.Owner || proof.Generation != source.Generation || proof.Key != key {
		t.Fatal("wrong signed native Gone")
	}
	record, err = (*owner).nativeVolumes.View(key)
	if err != nil || record.State.Pending != nil || record.State.LastID != originalRemove || record.State.Applied.Present {
		t.Fatal("restart replaced original Remove", err)
	}
	if _, err = docker.API.VolumeInspect(ctx, source.Owner.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("deleted native still present", err)
	}
	cli(0, "op", "show", "remove-data")
	cli(0, "op", "resume", "remove-data")
	cli(0, "--tenant", "tenant", "volume", "delete", "app/data", "--id", "remove-data", "--no-wait")
	if busy := cli(0, "op", "show", "busy-delete"); busy["state"] != "failed" {
		t.Fatal("refused delete not recorded as failed", busy)
	}
	inspected = cli(0, "--tenant", "tenant", "volume", "show", "app/data")
	if inspected["Phase"] != "Deleted" || len(registry().Deletions()) != 0 {
		t.Fatal("original deletion tombstone not observable")
	}
	t.Log("actual CLI shared busy refusal -> accepted Deleting -> native A3 Drain -> original nonforce Remove readback interrupted -> same owner DB/original Remove ID -> signed Gone/Deleted -> inspect/original result/resume; no native creation CLI/SQL/full quota claim")
}
