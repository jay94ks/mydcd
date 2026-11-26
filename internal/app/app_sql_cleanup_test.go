// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/moby/moby/client"
)

type sqlPublicFixture struct {
	EngineIDs [2]string
	Images    map[string]string
}

// The producer has already stopped. Read the ORIGINAL ingress journal before
// opening its Manager, then use its normal Drain/Gone and exact native pins.
type sqlIngressCleanup struct {
	bridges *network.Manager
	tunnels *network.TunnelManager
	owner   string
}

func (d sqlIngressCleanup) Acquire(context.Context, ingress.BackendSpec, string) error {
	return reconcile.ErrLease
}
func (d sqlIngressCleanup) Release(_ context.Context, b ingress.BackendSpec, consumer string) error {
	if !strings.HasPrefix(consumer, "ingress/") {
		return reconcile.ErrLease
	}
	found := 0
	for _, key := range d.tunnels.Keys() {
		row, err := d.tunnels.View(key)
		if err != nil {
			return err
		}
		pin, held := row.Consumers[consumer]
		if !held {
			continue
		}
		found++
		spec, err := network.DecodeTunnel(row.State.Applied.Spec)
		if err != nil || spec.Owner != d.owner || spec.Network != b.Network || pin.Generation != row.State.Applied.Generation {
			return reconcile.ErrLease
		}
		if err = d.tunnels.Return(network.TunnelLease{Key: key, Consumer: consumer, Pin: pin}); err != nil {
			return err
		}
	}
	for _, key := range d.bridges.Keys() {
		row, err := d.bridges.View(key)
		if err != nil {
			return err
		}
		pin, held := row.Consumers[consumer]
		if !held {
			continue
		}
		found++
		spec, err := network.DecodeBridge(row.State.Applied.Spec)
		if err != nil || spec.Owner != d.owner || pin.Generation != row.State.Applied.Generation {
			return reconcile.ErrLease
		}
		contains := false
		for _, pool := range spec.Pools {
			contains = contains || pool.Prefix.Contains(b.Address)
		}
		if !contains {
			return reconcile.ErrLease
		}
		if err = d.bridges.ReturnConsumer(key, consumer, pin.Generation); err != nil {
			return err
		}
	}
	if found > 1 {
		return reconcile.ErrLease
	}
	return nil
}

func TestManagedSQLCleanupHelper(t *testing.T) {
	cleanupManagedPrivateApp(t, os.Getenv("MYDC_SQL_CLEANUP"), "sql-fixture.json")
}

func TestManagedRouteAppCleanupHelper(t *testing.T) {
	cleanupManagedPrivateApp(t, os.Getenv("MYDC_ROUTE_CLEANUP"), "route-fixture.json")
}

func TestManagedDNSAppCleanupHelper(t *testing.T) {
	cleanupManagedPrivateApp(t, os.Getenv("MYDC_DNS_CLEANUP"), "dns-fixture.json")
}

func cleanupManagedPrivateApp(t *testing.T, path, manifest string) {
	t.Helper()
	if path == "" {
		t.Skip("owned private app fixture cleanup only")
	}
	cfg, err := config.LoadNode(path)
	if err != nil {
		t.Fatal(err)
	}
	_, installed, err := bootstrap.Effective(cfg)
	if err != nil {
		t.Fatal(err)
	}
	self, err := identity.Load(cfg.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	root := filepath.Dir(path)
	raw, err := os.ReadFile(filepath.Join(root, manifest))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var public sqlPublicFixture
	if json.Unmarshal(raw, &public) != nil {
		t.Fatal("original private app manifest")
	}
	var local config.NetworkLocal
	if err = cfg.Modules["network"].Decode(&local); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(local.DockerSocket, "unix://"+filepath.Join(root, "engine-")) {
		t.Fatal("refuse non-private Engine cleanup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	owner := engine.Owner(installed.Root.Cluster, self.Public)
	c, err := engine.Open(ctx, local.DockerSocket, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	info, err := c.API.Info(ctx, client.InfoOptions{})
	index := 0
	if cfg.Node.ID == "node-b" {
		index = 1
	} else if cfg.Node.ID != "node-a" {
		t.Fatal("foreign private app owner")
	}
	if err != nil || public.EngineIDs[index] == "" || info.Info.ID != public.EngineIDs[index] {
		t.Fatal("original private Engine identity differs", err)
	}
	bridges, err := network.OpenManager(filepath.Join(cfg.Node.StateDir, "network/journal.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer bridges.Close()
	tunnels, err := network.OpenTunnelManager(filepath.Join(cfg.Node.StateDir, "network/tunnel.db"), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnels.Close()
	ipath := filepath.Join(cfg.Node.StateDir, "ingress/runtime.db")
	if _, err = os.Stat(ipath); err == nil {
		db, err := storage.Open(ipath)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := db.Scan("instance/")
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		m, err := ingress.Open(ctx, ipath, sqlIngressCleanup{bridges, tunnels, owner})
		if err != nil {
			t.Fatal(err)
		}
		for key, b := range rows {
			key = strings.TrimPrefix(key, "instance/")
			var row struct {
				Revision, Generation uint64
				Spec                 ingress.Spec
				Gone                 bool
			}
			if json.Unmarshal(b, &row) != nil || row.Spec.Owner != owner {
				t.Error("original ingress cleanup identity")
				continue
			}
			if row.Gone {
				continue
			}
			if os.Getenv("MYDC_TEST_EXPECT_GONE") == "1" {
				t.Error("product left Ingress before cleanup")
			}
			if !row.Spec.Lifecycle.Drain {
				row.Spec.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
			}
			if err = m.Reconcile(ctx, key, row.Revision+1, row.Generation, &row.Spec); err != nil {
				t.Error(err)
			}
			status, e := m.Observe(key)
			if e != nil || !status.Gone {
				t.Error("original Ingress cleanup not Gone", e)
			}
		}
		_ = m.Close()
	}
	if cfg.Modules["workload"].Enabled {
		cleanupManagedTaskVolumes(t, ctx, c, cfg, bridges, map[string]any{"Cluster": installed.Root.Cluster, "NodeKey": self.Public, "PrivateEngineVerified": true, "PrivateImages": public.Images, "Tag": "private-engine-sql-only", "ExpectGone": os.Getenv("MYDC_TEST_EXPECT_GONE") == "1"})
	}
	t.Log(fmt.Sprintf("original private app owner %s cleanup complete", cfg.Node.ID))
}
