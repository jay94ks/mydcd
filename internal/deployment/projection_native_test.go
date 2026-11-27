// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type projectionLostReturn struct {
	*ProjectionStore
	fail bool
}

func (p *projectionLostReturn) ReturnInputs(ref workload.InputRef, consumer, key string, generation uint64) error {
	err := p.ProjectionStore.ReturnInputs(ref, consumer, key, generation)
	if err == nil && p.fail {
		p.fail = false
		return errors.New("original input return acknowledgement lost")
	}
	return err
}

func TestRealBoundaryPrivateProjectionMountAndOriginalClosure(t *testing.T) {
	verifyPrivateProjectionNative(t, false)
}

func TestRQ4RealSecretEnvironmentSpecifiedFileAndRedactedLogs(t *testing.T) {
	verifyPrivateProjectionNative(t, true)
}

func verifyPrivateProjectionNative(t *testing.T, environment bool) {
	t.Helper()
	tag := os.Getenv("SFC_DOCKER_TEST_OWNER")
	if tag == "" {
		t.Skip("requires owned Docker rollback prestate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var cluster [32]byte
	if _, err := rand.Read(cluster[:]); err != nil {
		t.Fatal(err)
	}
	var changes []func(*Needs)
	if environment {
		changes = append(changes, func(n *Needs) {
			n.Files[0].Target = "/etc/sfc/app-password"
			n.Files = append(n.Files, Projection{Key: "DB_PASSWORD", Target: "SFC_SECRET_ENV_VALUE", Mode: 0400, Kind: "env"})
		})
	}
	f, b, stage, gate := projectionFixtureCluster(t, cluster, changes...)
	defer stage.Destroy()
	owner := desired.Owner(f.cluster, b.d.Needs.Use.NodeKey)
	check, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := check.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+owner)})
	_ = check.Close()
	if err != nil || len(owned.Items) != 0 {
		t.Fatal("fresh native owner precondition", err)
	}
	// Register private-root cleanup before the fixture's native rollback, so
	// LIFO cleanup removes any native mount/container before its source files.
	root, err := os.MkdirTemp("/tmp", "sfc-projection-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if environment {
		manifest := os.Getenv("SFC_NATIVE_MANIFEST")
		if !filepath.IsAbs(backend) || !filepath.IsAbs(manifest) {
			t.Fatal("RQ4 requires prebuilt static backend and original ownership manifest")
		}
		file, err := os.OpenFile(manifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		err = json.NewEncoder(file).Encode(map[string]any{"Owner": owner, "Tag": tag, "Cluster": f.cluster, "NodeKey": b.d.Needs.Use.NodeKey, "Root": root, "CIDR": os.Getenv("SFC_DOCKER_TEST_CIDR"), "ImageRef": "sfc-boundary/" + tag + ":local"})
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal("persist ownership before native import", err, closeErr)
		}
	}
	var image *enginefixture.Fixture
	if backend != "" {
		image = enginefixture.OpenPrepared(t, ctx, owner, tag, nil, backend)
	} else {
		image = enginefixture.Open(t, ctx, owner, tag)
	}
	projectionPath := filepath.Join(root, "inputs")
	allowed := true
	current := func(ctx context.Context, b Binding) error {
		if !allowed {
			return ErrProjectionStore
		}
		return gate(ctx, b)
	}
	p, err := OpenProjections(projectionPath, f.cluster, b.d.Needs.Use.NodeKey, 4096, current)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	ref, err := p.Publish(ctx, b, stage, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	nPath, wPath := filepath.Join(root, "network.db"), filepath.Join(root, "workload.db")
	n, err := network.OpenManager(nPath, image.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	provider := &projectionLostReturn{ProjectionStore: p}
	w, err := workload.OpenManagerWithInputs(wPath, image.Client, n, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	prefix := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	bridgeKey := "network/projection"
	bridge := network.BridgeSpec{Schema: 1, Network: "projection", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "projection", Network: "projection", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
	if err = n.Desired(bridgeKey, 1, 1, &bridge, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	got, err := image.Client.Image(ctx, image.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"SFC_PROJECTION_FILE": b.d.Needs.Files[0].Target}
	if environment {
		env["SFC_SECRET_LOG_FIXTURE"] = "1"
	}
	process, err := workload.ResolveImageProcess(got, workload.ProcessOverrides{User: fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid()), Environment: env, Healthcheck: &container.HealthConfig{Test: []string{"CMD", "/backend", "--projection-probe"}, Interval: time.Second, Timeout: time.Second, Retries: 2}})
	if err != nil {
		t.Fatal(err)
	}
	taskKey := projectionTask(b)
	spec := workload.ContainerSpec{Schema: 1, Node: owner, Image: image.Image, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000, Process: &process, Inputs: &ref}
	if err = w.Desired(taskKey, 4, ref.Generation, &spec, 2); err != nil {
		t.Fatal(err)
	}
	allowed = false
	if err = w.Step(ctx, taskKey); err == nil {
		t.Fatal("create proceeded without current input admission")
	}
	before, err := w.View(taskKey)
	if err != nil || before.State.Pending != nil || before.State.Applied.Present || before.State.LastID != 1 {
		t.Fatal("known precreate rejection lost its terminal evidence", err)
	}
	pins, err := p.journal.Read(ref.Key)
	if err != nil || len(pins.Consumers) != 0 {
		t.Fatal("precreate gate failure left input pin", err)
	}
	allowed = true
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("native private mount Apply", err)
	}
	var nativeID string
	for {
		status, err := w.Status(ctx, taskKey)
		if err != nil {
			t.Fatal(err)
		}
		if status.Ready {
			nativeID = status.NativeID
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("nonroot secret read/read-only mount probe", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if environment {
		native, err := image.Client.API.ContainerInspect(ctx, nativeID, client.ContainerInspectOptions{})
		if err != nil || native.Container.Config == nil || !slices.Contains(native.Container.Config.Env, "SFC_SECRET_ENV_VALUE=private-db-value") {
			t.Fatal("Secret value was not supplied at native create", err)
		}
		if slices.Contains(process.Env, "SFC_SECRET_ENV_VALUE=private-db-value") {
			t.Fatal("runtime Secret mutated frozen image process")
		}
		view, err := w.View(taskKey)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(view)
		if err != nil || strings.Contains(string(encoded), "private-db-value") {
			t.Fatal("Secret entered native journal", err)
		}
		target := containerops.Target{Cluster: f.cluster, Owner: b.d.Needs.Use.NodeKey, Binding: b.Digest(), Tenant: b.d.Needs.Use.Tenant, App: b.d.Needs.Use.App, Service: b.d.Needs.Use.Service, Node: b.d.Needs.Use.Node, Instance: taskKey, Generation: ref.Generation, Revision: 4, NativeID: nativeID}
		query := containerops.Query{Schema: 1, Selection: containerops.Selection{App: target.App, Service: target.Service}, Kind: "logs", Tail: 200, Stdout: true, Stderr: true, MaxBytes: containerops.MaxOutput}
		logs, err := w.ObserveContainer(ctx, target, query)
		if err != nil || strings.Contains(string(logs.Stdout)+string(logs.Stderr), "private-db-value") || !strings.Contains(string(logs.Stdout), "«가림: tenant/runtime/DB_PASSWORD»") {
			t.Fatal("finite logs exposed supplied Secret or lost provenance", err)
		}
		target.StartedAt = logs.Target.StartedAt
		follow, cancelFollow := context.WithCancel(ctx)
		var followed []byte
		err = w.FollowContainerLogs(follow, target, query, func(record containerops.SessionRecord) error {
			if record.Kind == "stdout" || record.Kind == "stderr" {
				followed = append(followed, record.Data...)
				if strings.Contains(string(followed), "«가림: tenant/runtime/DB_PASSWORD»") {
					cancelFollow()
				}
			}
			return nil
		})
		cancelFollow()
		if strings.Contains(string(followed), "private-db-value") || !strings.Contains(string(followed), "«가림: tenant/runtime/DB_PASSWORD»") {
			t.Fatal("follow exposed Secret or omitted protected output", err)
		}
	}
	// Removal drains admission and waits for the original native consumer;
	// it must not dispatch a Remove or release its private inputs yet.
	if err = p.Drain(ctx, ref, 2); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("live container did not pin private files", err)
	}
	draining, err := p.journal.Read(ref.Key)
	if err != nil || draining.State.Pending != nil || !draining.State.Applied.Present || draining.State.Desired.Present || draining.Pins == nil || !draining.Pins.Draining || len(draining.Consumers) != 1 || len(draining.Pins.Active) != 1 {
		t.Fatal("Drain did not preserve original live input consumer", err)
	}
	drainedStatus, err := w.Status(ctx, taskKey)
	if err != nil || !drainedStatus.Ready || drainedStatus.NativeID != nativeID {
		t.Fatal("Drain changed original running container", err)
	}
	if _, err = p.SecretClosure(ref, f.na); err == nil {
		t.Fatal("live native mount signed Gone")
	}
	consumer, _ := projectionConsumer(t, f, b)
	original, err := p.InspectInputs(ctx, ref, consumer, taskKey, ref.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(original.Files) != len(stage.files) {
		t.Fatal("Drain changed original projection inventory")
	}
	for i, file := range original.Files {
		value, readErr := os.ReadFile(file.Source)
		valid := readErr == nil && bytes.Equal(value, stage.files[i].Data)
		clear(value)
		if !valid {
			t.Fatal("Drain removed or changed pinned private file", readErr)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	p, err = OpenProjections(projectionPath, f.cluster, b.d.Needs.Use.NodeKey, 4096, current)
	if err != nil {
		t.Fatal(err)
	}
	provider.ProjectionStore = p
	w, err = workload.OpenManagerWithInputs(wPath, image.Client, n, provider)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := p.InspectInputs(ctx, ref, consumer, taskKey, ref.Generation)
	if err != nil || recovered.Pin != original.Pin {
		t.Fatal("reopen changed native input pin", err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original task/input recovery", err)
	}
	resumed, err := w.View(taskKey)
	if err != nil || resumed.State.LastID != 2 {
		t.Fatal("reopen dispatched a new creation attempt", err)
	}
	status, err := w.Status(ctx, taskKey)
	if err != nil || status.NativeID != nativeID {
		t.Fatal("recovery recreated native task", err)
	}
	allowed = false
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original Running result incorrectly required reactivation", err)
	}
	timeout := 1
	if _, err = image.Client.API.ContainerStop(ctx, nativeID, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	// restart=no preserves an exited original. Step acknowledges that original
	// creation; it does not request another Start or need a new activation grant.
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("original exited task recovery", err)
	}
	stopped, err := w.Status(ctx, taskKey)
	if err != nil || stopped.Running || stopped.NativeID != nativeID {
		t.Fatal("maintenance restarted or replaced exited original", err)
	}
	if _, err = p.AcquireInputs(ctx, ref, consumer, taskKey, ref.Generation); err == nil {
		t.Fatal("drained/revoked inputs admitted a new activation")
	}
	if err = w.Desired(taskKey, 5, ref.Generation, nil, 2); err != nil {
		t.Fatal(err)
	}
	provider.fail = true
	if err = w.Step(ctx, taskKey); err == nil {
		t.Fatal("lost input return acknowledgement became completed removal")
	}
	pending, err := w.View(taskKey)
	if err != nil || pending.State.Pending == nil || pending.State.Pending.Phase != reconcile.RecoveryRequired {
		t.Fatal("original Remove uncertainty lost", err)
	}
	if gone, err := w.Gone(ctx, taskKey, 5, ref.Generation); err != nil || gone {
		t.Fatal("unsettled removal reported complete", err)
	}
	if err = p.Drain(ctx, ref, 2); err != nil {
		t.Fatal("last native return/files retirement", err)
	}
	proof, err := p.SecretClosure(ref, f.na)
	if err != nil {
		t.Fatal("positive original file/mount closure", err)
	}
	released, err := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, proof)
	if err != nil {
		t.Fatal("original Secret usage release", err)
	}
	if err = p.Forget(ref, released.Inventory); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, taskKey); err != nil {
		t.Fatal("late original return could not settle after input closure", err)
	}
	settled, err := w.View(taskKey)
	if err != nil || settled.State.LastID != pending.State.LastID || settled.State.Pending != nil {
		t.Fatal("new operation replaced original lost return", err)
	}
	if gone, err := w.Gone(ctx, taskKey, 5, ref.Generation); err != nil || !gone {
		t.Fatal("original native closure after late return", err)
	}
	for _, file := range original.Files {
		if _, err = os.Stat(file.Source); !os.IsNotExist(err) {
			t.Fatal("source retained after last native/reference closure", err)
		}
	}
	if err = n.Desired(bridgeKey, 10, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal("Bridge reference return/removal", err)
	}
	t.Log("actual nonroot Engine secret-file/read-only bind/health, original task ID and synced input pin across reopen, current activation gate and permission-independent native removal, final filesystem Gone/signature/shared usage release")
}
