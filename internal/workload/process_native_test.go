// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/workload"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRealBoundaryFrozenImageProcessAndOriginalJournal(t *testing.T) {
	tag := os.Getenv("SFC_DOCKER_TEST_OWNER")
	manifest, backend := os.Getenv("SFC_NATIVE_MANIFEST"), os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if tag == "" || manifest == "" || backend == "" {
		t.Skip("requires owned Docker rollback prestate, manifest and user-prebuilt backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cluster, node := sha256.Sum256([]byte("process-cluster/"+tag)), sha256.Sum256([]byte("process-node/"+tag))
	owner := engine.Owner(cluster, node)
	t.Logf("nativeOwner=%s fixtureTag=%s", owner, tag)
	root, err := os.MkdirTemp("", "sfc-l1-sdk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("preserved original SDK recovery root", root)
		} else if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	public := map[string]any{"Owner": owner, "Tag": tag, "Cluster": cluster, "NodeKey": node, "Root": root, "CIDR": os.Getenv("SFC_DOCKER_TEST_CIDR"), "ImageRef": "sfc-boundary/" + tag + ":local"}
	file, err := os.OpenFile(manifest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = json.NewEncoder(file).Encode(public)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("ownership must precede native import", err, closeErr)
	}
	f := enginefixture.OpenPrepared(t, ctx, owner, tag, []string{`USER 10001:10001`, `ENV IMAGE_DEFAULT=original OVERRIDE=old`, `ENTRYPOINT ["/backend"]`, `CMD ["image-default"]`}, backend, map[string][]byte{"lifecycle-ready": []byte("ready\n")})
	nPath, wPath := filepath.Join(root, "network.db"), filepath.Join(root, "workload.db")
	n, err := network.OpenManager(nPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	w, err := workload.OpenManager(wPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	prefix := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	bridgeKey := "network/image-process"
	bridge := network.BridgeSpec{Schema: 1, Network: "image-process", Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "process", Network: "image-process", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
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
	if image.Config.User != "10001:10001" || !reflect.DeepEqual(image.Config.Entrypoint, []string{"/backend"}) {
		t.Fatal("image metadata precondition")
	}
	var specs []workload.ContainerSpec
	keys := []string{"workload/image-inherit", "workload/image-clear"}
	for i, key := range keys {
		overrides := workload.ProcessOverrides{Environment: map[string]string{"OVERRIDE": "new", "EMPTY": ""}, Healthcheck: &container.HealthConfig{Test: []string{"CMD", "/backend", "--probe"}, Interval: time.Second, Timeout: time.Second, Retries: 2}}
		if i == 1 {
			entry := []string{}
			command := []string{"/backend", "--shutdown-delay", "150ms"}
			overrides.Entrypoint, overrides.Command = &entry, &command
			overrides.StopSignal = "SIGQUIT"
		}
		process, err := workload.ResolveImageProcess(image, overrides)
		if err != nil {
			t.Fatal(err)
		}
		spec := workload.ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000, Process: &process}
		if i == 1 {
			spec.IPv4 = spec.IPv4.Next()
			spec.Stop = &engine.StopPolicy{GraceSeconds: 2, Signal: "SIGQUIT"}
		}
		specs = append(specs, spec)
		if err = w.Desired(key, uint64(i+2), uint64(i+2), &spec, 4); err != nil {
			t.Fatal(err)
		}
		if err = w.Step(ctx, key); err != nil {
			t.Fatal("native process apply", i, err)
		}
		state, err := w.View(key)
		if err != nil || state.State.Pending != nil || !state.State.Applied.Present {
			t.Fatal("creation not durably applied", err)
		}
		status, err := w.Status(ctx, key)
		if err != nil || !status.Running || !status.HealthConfigured || status.Ready != (status.Health == "healthy") {
			t.Fatal("Running/Healthy conflated", status, err)
		}
		target, err := w.ProbeTarget(ctx, key, state.State.Applied.Generation, state.State.Desired.Revision)
		if err != nil || target.Status.NativeID != status.NativeID || target.IPv4 != spec.IPv4 || target.Status.Exit != nil {
			t.Fatal("original native probe target", err)
		}
		run := sha256.Sum256([]byte("process-native-read/" + key))
		lease, err := w.BorrowReadProbe(ctx, key, target.Generation, target.Revision, target.Status.NativeID, hex.EncodeToString(run[:]), sha256.Sum256([]byte("file-call")))
		returned := false
		defer func() {
			if !returned && lease.Pin.Generation != 0 {
				if e := w.ReturnReadProbe(lease); e != nil {
					t.Error("original read consumer cleanup", e)
				}
			}
		}()
		if err != nil {
			t.Fatal("read pin", err)
		}
		// Actual SDK stat/A3 and original container; current cluster permission
		// is a fixture callback, not an authentication/managed app proof.
		file, readErr := w.ReadProbeFile(ctx, lease, contract.FileProbe{Service: "fixture", Path: "/backend", Kind: "regular"}, func(context.Context) error { return nil })
		if readErr == nil {
			exerciseContainerFileContent(t, ctx, w, lease)
		}
		if err = w.ReturnReadProbe(lease); err != nil {
			t.Fatal("read pin return", err)
		}
		returned = true
		if readErr != nil || !file.Exists || !file.Match || file.Kind != "regular" {
			t.Fatal("actual owned file probe", readErr)
		}
		exerciseContainerExecProbes(t, ctx, w, key, root, cluster, node)
		got, err := f.Client.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Container.Config.Entrypoint, process.Entrypoint) || !slices.Equal(got.Container.Config.Cmd, process.Command) || !slices.Equal(got.Container.Config.Env, process.Env) || got.Container.Config.User != process.User {
			t.Fatal("Engine reinserted or changed frozen image config")
		}
		if i == 1 && (got.Container.Config.StopTimeout == nil || *got.Container.Config.StopTimeout != 2 || got.Container.Config.StopSignal != "SIGQUIT") {
			t.Fatal("declared per-service stop policy lost before native Start")
		}
		// No duplicated Command/Env authority can enter the journal.
		conflict := spec
		conflict.Command = []string{"/different"}
		raw, _ := json.Marshal(conflict)
		if _, err = workload.DecodeContainer(string(raw)); err == nil {
			t.Fatal("dual process authority accepted")
		}
	}
	ids := map[string]string{}
	for _, key := range keys {
		for {
			status, err := w.Status(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			if status.Ready {
				ids[key] = status.NativeID
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("actual healthcheck", ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	timeout := 1
	if _, err = f.Client.API.ContainerStop(ctx, ids[keys[0]], client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	status, err := w.Status(ctx, keys[0])
	if err != nil || status.Running || status.Ready {
		t.Fatal("read observation restarted a stopped process", status, err)
	}
	deadRun := sha256.Sum256([]byte("stopped-container-check"))
	deadLease, err := w.BorrowReadProbe(ctx, keys[0], 2, 2, status.NativeID, hex.EncodeToString(deadRun[:]), sha256.Sum256([]byte("stopped-connect")))
	deadReturned := false
	defer func() {
		if !deadReturned && deadLease.Pin.Generation != 0 {
			if err := w.ReturnReadProbe(deadLease); err != nil {
				t.Error("stopped read pin cleanup", err)
			}
		}
	}()
	if err != nil {
		t.Fatal("positive stopped Task could not be checked", err)
	}
	// The same fixture already stopped this original container. A Background
	// context cannot enter the finite native TCP dial path: this result must
	// come from the owned stopped observation, without connecting to its old IP.
	dead, err := w.ReadProbeTCP(context.Background(), deadLease, contract.TCPProbe{Service: "fixture", Port: 8080}, func(context.Context) error { return nil })
	if err != nil || dead.Connected || len(dead.Data) != 0 {
		t.Fatal("stopped container did not reach the script's dead branch", dead, err)
	}
	if err = w.ReturnReadProbe(deadLease); err != nil {
		t.Fatal("stopped read pin return", err)
	}
	deadReturned = true
	exerciseContainerCheckControls(t, ctx, w, keys[0], root, cluster, node)
	exerciseRequestedContainerControl(t, ctx, w, keys[0], root, node)
	// A real one-shot command can exit before Start's first inspect. It must
	// remain the same exited original across maintenance and DB reopen.
	probeCommand := []string{"--exit-code", "0"}
	oneShot, err := workload.ResolveImageProcess(image, workload.ProcessOverrides{Command: &probeCommand, Healthcheck: &container.HealthConfig{Test: []string{"NONE"}}})
	if err != nil {
		t.Fatal(err)
	}
	jobKey := "workload/image-once"
	jobSpec := workload.ContainerSpec{Schema: 1, Node: owner, Image: f.Image, Bridge: bridgeKey, BridgeGeneration: 1, IPv4: prefix.Addr().Next().Next().Next().Next(), Memory: 32 << 20, NanoCPU: 100000000, Process: &oneShot}
	if err = w.Desired(jobKey, 4, 4, &jobSpec, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, jobKey); err != nil {
		t.Fatal("one-shot Start/fast exit", err)
	}
	var jobStatus workload.ContainerStatus
	for {
		jobStatus, err = w.Status(ctx, jobKey)
		if err != nil {
			t.Fatal(err)
		}
		if jobStatus.Exit != nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("one-shot did not report positive exit", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if jobStatus.Running || jobStatus.Ready || jobStatus.Exit.Code != 0 {
		t.Fatal("one-shot terminal state", jobStatus)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	n, err = network.OpenManager(nPath, f.Client)
	if err != nil {
		t.Fatal(err)
	}
	w, err = workload.OpenManager(wPath, f.Client, n)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		if err = w.Step(ctx, key); err != nil {
			t.Fatal("same journal process recovery", err)
		}
		status, err = w.Status(ctx, key)
		if err != nil || status.Running != (i != 0) || status.NativeID != ids[key] {
			t.Fatal("recovery replaced original ID/pin", status, err)
		}
		record, _ := w.View(key)
		if record.State.LastID != 1 {
			t.Fatal("recovery dispatched another create")
		}
		if err = w.Desired(key, uint64(10+i), uint64(i+2), nil, 4); err != nil {
			t.Fatal(err)
		}
		if err = w.Step(ctx, key); err != nil {
			t.Fatal("original process removal", err)
		}
		gone, err := w.Gone(ctx, key, uint64(10+i), uint64(i+2))
		if err != nil || !gone {
			t.Fatal("native closure", gone, err)
		}
	}
	if err = w.Step(ctx, jobKey); err != nil {
		t.Fatal("one-shot same DB maintenance", err)
	}
	settled, err := w.Status(ctx, jobKey)
	if err != nil || settled.Running || settled.Ready || settled.NativeID != jobStatus.NativeID || settled.Exit == nil || *settled.Exit != *jobStatus.Exit {
		t.Fatal("one-shot original was restarted or replaced", err)
	}
	if err = w.Desired(jobKey, 12, 4, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = w.Step(ctx, jobKey); err != nil {
		t.Fatal("one-shot explicit retirement", err)
	}
	if gone, err := w.Gone(ctx, jobKey, 12, 4); err != nil || !gone {
		t.Fatal("one-shot native/consumer closure", gone, err)
	}
	if err = n.Desired(bridgeKey, 20, 1, nil, 4); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal("bridge pin return/removal", err)
	}
	t.Log("actual imported image defaults/explicit empty entrypoint -> frozen native configuration/health; restart=no preserves stopped and one-shot original ID/exit across reopen; explicit native closure returns dependency pins")
}
