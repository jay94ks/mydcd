// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/client"
)

func TestRealBoundaryCommittedGoalBridgeProjection(t *testing.T) {
	tag, cidr, manifest := os.Getenv("MYDC_DOCKER_TEST_OWNER"), os.Getenv("MYDC_DOCKER_TEST_CIDR"), os.Getenv("MYDC_NATIVE_MANIFEST")
	if tag == "" || cidr == "" || manifest == "" || os.Geteuid() != 0 {
		t.Skip("requires user-prebuilt binary and owned Docker/host rollback prestate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cluster := sha256.Sum256([]byte(tag + "/goal-bridge"))
	f := makeFixtureCluster(t, cluster)
	input := smallCompose(t)
	delete(input.Services, "web")
	service := input.Services["db"]
	service.CPUs, service.Memory = "0.1", "16m"
	service.Networks = map[string]Attachment{"app": {IPv4: netip.MustParsePrefix(cidr).Addr().Next().Next().String()}}
	service.MyDC = ServiceExtension{Node: "node-a"}
	service.Secrets = nil
	service.Volumes = nil
	service.Environment = nil
	service.Healthcheck = nil
	input.Services["db"] = service
	input.Volumes = nil
	input.Secrets = nil
	input.Networks = map[string]ComposeNetwork{"app": {MyDC: NetworkExtension{MTU: 1280, Pools: map[string]PoolDeclaration{"node-a": {CIDR: cidr, Gateway: netip.MustParsePrefix(cidr).Addr().Next().String()}}}}}
	plan, err := Compile(input, f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	key := ResourceKey("bridge", "tenant", "php-mysql", "app/node-a")
	var source Step
	for _, step := range plan.Steps() {
		if step.Key == key {
			source = step
		}
	}
	g := GoalCommand{Schema: 1, Cluster: cluster, Tenant: "tenant", App: "php-mysql", Deployment: "deploy", Kind: "bridge", Node: "node-a", Owner: public(f.na), Config: source.Goal}
	raw, _ := json.Marshal(g)
	projected, err := DecodeGoalResources(cluster, key, state.Object{Present: true, Generation: 11, Revision: 11, Value: string(raw)})
	if err != nil || projected.Bridge == nil {
		t.Fatal("native projection", err)
	}
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", projected.Bridge.Owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	specBytes, _ := json.Marshal(*projected.Bridge)
	id, err := c.Identity("bridge", key, reconcile.Resource{Present: true, Generation: 11, Spec: string(specBytes)})
	if err != nil {
		t.Fatal(err)
	}
	declaration := struct {
		Owner, Key, Name string
		Generation       uint64
		Labels           map[string]string
		Spec             json.RawMessage
	}{c.Owner, key, id.Name, 11, id.Labels, specBytes}
	manifestBytes, _ := json.Marshal(declaration)
	if err = os.WriteFile(manifest, manifestBytes, 0644); err != nil {
		t.Fatal(err)
	}
	filters := client.Filters{}.Add("label", "org.mydc.owner="+c.Owner)
	path := filepath.Join(t.TempDir(), "network.db")
	var manager *network.Manager
	t.Cleanup(func() {
		if manager != nil {
			_ = manager.Close()
			manager = nil
		}
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		rows, err := c.API.NetworkList(clean, client.NetworkListOptions{Filters: filters})
		if err != nil {
			t.Error(err)
			return
		}
		for _, row := range rows.Items {
			if !t.Failed() {
				t.Error("product left owned network")
			}
			current, err := c.API.NetworkInspect(clean, row.ID, client.NetworkInspectOptions{})
			if err != nil {
				t.Error(err)
				continue
			}
			if !id.Matches(current.Network.Name, current.Network.Labels) || current.Network.Name != id.Name || len(current.Network.Containers) != 0 {
				t.Error("fallback ownership/endpoints mismatch")
				continue
			}
			if _, err = c.API.NetworkRemove(clean, row.ID, client.NetworkRemoveOptions{}); err != nil {
				t.Error(err)
			}
		}
	})
	before, err := c.API.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil || len(before.Items) != 0 {
		t.Fatal("owner initially nonempty", err)
	}
	manager, err = network.OpenManager(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Desired(key, 11, 11, projected.Bridge, 4); err != nil {
		t.Fatal(err)
	}
	if err = manager.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire(ctx, key, "projection-consumer", 11)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Spec.Network != projected.Network.ID || lease.Spec.Owner != c.Owner || lease.Spec.Pools[0].Prefix != netip.MustParsePrefix(cidr) {
		t.Fatal("native source mismatch")
	}
	originalID := lease.NetworkID
	record, err := manager.View(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager = nil
	manager, err = network.OpenManager(path, c)
	if err != nil {
		t.Fatal(err)
	}
	again, err := manager.InspectConsumer(ctx, key, "projection-consumer", 11)
	restored, readErr := manager.View(key)
	if err != nil || readErr != nil || again.NetworkID != originalID || again.Pin != lease.Pin || restored.State.LastID != record.State.LastID {
		t.Fatal("same native ID/source/pin DB restore", err, readErr)
	}
	if err = manager.Return(again); err != nil {
		t.Fatal(err)
	}
	if err = manager.Desired(key, 12, 11, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = manager.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	gone, err := manager.Gone(ctx, key, 12, 11, *projected.Bridge)
	if err != nil || !gone {
		t.Fatal("original native Gone", gone, err)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager = nil
	t.Log(fmt.Sprintf("source gen11/key/Goal -> typed Bridge -> real SDK/kernel/native ID/pin -> same DB -> original removal/Gone; owner=%s", c.Owner))
}
