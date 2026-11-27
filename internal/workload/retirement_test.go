// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/tests/enginefixture"
)

type lostWorkloadRetirement struct {
	*DockerDriver
	loseApply, loseRetire bool
}

func (d *lostWorkloadRetirement) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	outcome, err := d.DockerDriver.Execute(ctx, key, op)
	if err == nil && d.loseApply {
		d.loseApply = false
		return outcome, errors.New("original Apply completed; ACK lost")
	}
	return outcome, err
}

func (d *lostWorkloadRetirement) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	outcome, err := d.DockerDriver.ExecuteCheckpoint(ctx, key, op, save)
	if err == nil && d.loseApply {
		d.loseApply = false
		return outcome, errors.New("original Apply completed; ACK lost")
	}
	return outcome, err
}
func (d *lostWorkloadRetirement) Retire(ctx context.Context, key string, op reconcile.Operation, evidence []byte, save func([]byte) error) (bool, error) {
	closed, err := d.DockerDriver.Retire(ctx, key, op, evidence, save)
	if err == nil && closed && d.loseRetire {
		d.loseRetire = false
		return true, errors.New("original retirement completed; ACK lost")
	}
	return closed, err
}

func TestRealBoundaryOriginalApplyRetirementAndSameIDRecovery(t *testing.T) {
	owner := os.Getenv("SFC_DOCKER_TEST_OWNER")
	if owner == "" {
		t.Skip("requires owned Docker rollback prestate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	f := enginefixture.OpenConfigured(t, ctx, owner, owner, []string{`USER 10001:10001`})
	root := t.TempDir()
	networkPath, workloadPath := filepath.Join(root, "network.db"), filepath.Join(root, "workload.db")
	n, err := network.OpenManager(networkPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	w, err := OpenManager(workloadPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	prefix := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	bridgeKey, taskKey := "network/retirement", "workload/retirement"
	bridge := network.BridgeSpec{Schema: 1, Network: "retirement", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "retirement", Network: "retirement", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	if err = n.Desired(bridgeKey, 1, 1, &bridge, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	image, err := f.Client.Image(ctx, f.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	process, err := ResolveImageProcess(image, ProcessOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	spec := ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000, Process: &process}
	if err = w.Desired(taskKey, 2, 2, &spec, 4); err != nil {
		t.Fatal(err)
	}
	lost := &lostWorkloadRetirement{DockerDriver: w.driver, loseApply: true, loseRetire: true}
	if err = w.journal.Step(ctx, taskKey, lost); err == nil {
		t.Fatal("lost Apply ACK reported success")
	}
	r, err := w.View(taskKey)
	if err != nil || r.State.Pending == nil || r.State.LastID != 1 || r.State.Applied.Present {
		t.Fatal("original uncertain Apply lost", err)
	}
	original := *r.State.Pending
	if err = w.Desired(taskKey, 3, 2, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.journal.Step(ctx, taskKey, lost); err == nil {
		t.Fatal("lost retirement ACK reported completion")
	}
	r, err = w.View(taskKey)
	if err != nil || r.State.Pending == nil || r.State.Pending.ID != original.ID || r.State.Pending.Target != original.Target || r.State.Pending.Phase != reconcile.Retiring || r.State.Applied.Present || len(r.Retirement) == 0 {
		t.Fatal("retirement replaced original Apply", err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	n, err = network.OpenManager(networkPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	w, err = OpenManager(workloadPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("same ID terminal receipt recovery", err)
	}
	r, err = w.View(taskKey)
	if err != nil || r.State.Pending != nil || r.State.Applied.Present || r.State.LastID != original.ID || len(r.Retirement) != 0 {
		t.Fatal("retirement fabricated Apply or another operation", err)
	}
	if gone, e := w.Gone(ctx, taskKey, 3, 2); e != nil || !gone {
		t.Fatal("original native closure", e)
	}
	br, err := n.View(bridgeKey)
	if err != nil || len(br.Consumers) != 0 {
		t.Fatal("original dependency not returned", err)
	}
	if err = n.Desired(bridgeKey, 4, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	t.Log("actual original Apply/native process -> lost ACK -> same ID Retiring/positive native receipt -> native Stop/Remove/dependency return -> lost ACK -> same DB terminal receipt; no fabricated Applied/NotApplied or replacement create")
}
