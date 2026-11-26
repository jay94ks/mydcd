// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// Actual Manager/journal/SDK decoder; only Engine responses are injected.
// This does not claim Docker/OS or a Volume writer is ready.
func networkIdentityFixture(t *testing.T) (*Manager, *startFixture) {
	t.Helper()
	f := makeStartFixture(t)
	f.onStart = func() error {
		f.native.State = &container.State{Status: container.StateRunning, Running: true, Pid: 123, StartedAt: "2026-11-18T01:00:00Z"}
		return nil
	}
	m, err := OpenManager(filepath.Join(t.TempDir(), "workload.db"), f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.Desired("task", 1, 1, &f.spec, 4); err != nil {
		t.Fatal(err)
	}
	if err := m.Step(context.Background(), "task"); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func TestNetworkIdentityKeepsOriginalOwnershipAndGeneration(t *testing.T) {
	m, f := networkIdentityFixture(t)
	id, running, err := m.NetworkIdentity(context.Background(), "task", 1)
	if err != nil || id != f.native.ID || !running || f.starts != 1 {
		t.Fatal("original network identity unavailable", id, running, err)
	}
	if _, _, err := m.NetworkIdentity(context.Background(), "task", 2); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("a different allocation generation borrowed the original container", err)
	}
	for name, change := range map[string]func(*startFixture){
		"owner": func(f *startFixture) { f.native.Config.Labels["org.mydc.owner"] = "foreign" },
		"address": func(f *startFixture) {
			f.native.NetworkSettings.Networks["fixture-bridge"].IPAddress = netip.MustParseAddr("192.0.2.99")
		},
		"mount": func(f *startFixture) {
			f.native.HostConfig.Mounts = []mount.Mount{{Type: mount.TypeVolume, Source: "foreign", Target: "/data"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, f := networkIdentityFixture(t)
			change(f)
			if _, running, err := m.NetworkIdentity(context.Background(), "task", 1); err == nil || running {
				t.Fatal("foreign native state admitted as a DNS origin")
			}
		})
	}
	f.native.State.Running, f.native.State.Status = false, container.StateExited
	if _, running, err := m.NetworkIdentity(context.Background(), "task", 1); err != nil || running {
		t.Fatal("stopped container became live network provenance", err)
	}
}

func TestNetworkIdentityRejectsChangingJournalAndUncertainStart(t *testing.T) {
	m, f := networkIdentityFixture(t)
	f.onInspect = func() error {
		f.onInspect = nil
		return m.Desired("task", 2, 2, &f.spec, 4)
	}
	if _, _, err := m.NetworkIdentity(context.Background(), "task", 1); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("journal changed during native inspection", err)
	}
	f = makeStartFixture(t)
	f.onStart = func() error { return io.ErrUnexpectedEOF }
	pending, err := OpenManager(filepath.Join(t.TempDir(), "pending.db"), f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	if err := pending.Desired("task", 1, 1, &f.spec, 4); err != nil {
		t.Fatal(err)
	}
	if err := pending.Step(context.Background(), "task"); err == nil {
		t.Fatal("lost Start reply became confirmed")
	}
	if _, running, err := pending.NetworkIdentity(context.Background(), "task", 1); !errors.Is(err, reconcile.ErrPending) || running || f.starts != 1 {
		t.Fatal("unknown Start was admitted or replayed", err)
	}
}
