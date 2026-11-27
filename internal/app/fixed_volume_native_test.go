// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

func TestS1RealBoundaryFixedVolumeCLIAppAndOriginalData(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppFixedVolume, true, false)
}

func (f *fixedAppNativeFixture) rejectChange(t *testing.T, ctx context.Context, id, action string, expected uint64, payload any) {
	t.Helper()
	raw, err := json.Marshal(struct {
		Schema   uint8  `json:"schema"`
		Action   string `json:"action"`
		Expected uint64 `json:"expected"`
		Payload  any    `json:"payload"`
	}{1, action, expected, payload})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.home, id+".json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.cli(t, ctx, -1, "manage", "apply", "--request-id", id, "--change", path)
}

type fixedAppNativeFixture struct {
	base, source, home, profile, binary string
	ready                               volumes.NativeReady
	before                              os.FileInfo
	tenant                              string // global --tenant for tenant commands
}

func (f *fixedAppNativeFixture) cli(t *testing.T, ctx context.Context, want int, args ...string) map[string]json.RawMessage {
	t.Helper()
	args = withTenant(f.tenant, args)
	output, diagnostic, err := runManagedCLICommand(ctx, f.binary, f.home, f.profile, args, nil)
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if want >= 0 && code != want || want < 0 && (code == 0 || code == 2) {
		t.Fatal("fixed CLI", args, code, string(diagnostic), string(output))
	}
	var reply map[string]json.RawMessage
	if len(output) > 0 && json.Unmarshal(output, &reply) != nil {
		t.Fatal("fixed CLI JSON", args, string(output))
	}
	return reply
}

func fixedNativeWait(t *testing.T, ctx context.Context, label string, check func() bool) {
	t.Helper()
	for !check() {
		select {
		case <-ctx.Done():
			t.Fatal(label, ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func prepareFixedAppNative(t *testing.T, ctx context.Context, r *Runtime, root string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) *fixedAppNativeFixture {
	t.Helper()
	f := prepareFixedAppNativeSource(t, ctx, r, root, p, read, change)
	verifyEmbeddedFixedWriter(t, ctx, r, root, p, read, change, f.ready)
	return f
}

// Source registration is shared with the real embedded registry fixture. It
// doesn't run the old stand-in writer or repeat the S1 app/readonly scenarios.
func prepareFixedAppNativeSource(t *testing.T, ctx context.Context, r *Runtime, root string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) *fixedAppNativeFixture {
	t.Helper()
	owner := engine.Owner(p.Cluster, r.Identity.Public)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		// Capture the original fixture process before the existing rollback
		// removes it. Never query another owner's containers or log secrets.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
		if err != nil {
			t.Log("fixed Task failure inspect", err)
			return
		}
		defer c.Close()
		rows, err := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+owner).Add("label", "org.sfc.kind=container")})
		if err != nil {
			t.Log("fixed Task failure list", err)
			return
		}
		for _, row := range rows.Items {
			got, err := c.API.ContainerInspect(ctx, row.ID, client.ContainerInspectOptions{})
			if err != nil {
				t.Log("fixed Task failure inspect", err)
				continue
			}
			t.Logf("original fixed Task %s state=%+v mounts=%+v user=%q", row.ID, got.Container.State, got.Container.Mounts, got.Container.Config.User)
			logs, err := c.API.ContainerLogs(ctx, row.ID, client.ContainerLogsOptions{ShowStderr: true, Tail: "8"})
			if err == nil {
				raw, readErr := io.ReadAll(io.LimitReader(logs, 4096))
				_ = logs.Close()
				t.Logf("fixed backend diagnostic %q read=%v", raw, readErr)
			}
		}
	})
	image, tag, hostNS := os.Getenv("SFC_STORAGE_TEST_ROOT"), os.Getenv("SFC_STORAGE_TEST_OWNER"), os.Getenv("SFC_STORAGE_HOST_MOUNT_NS")
	if image == "" || tag == "" || hostNS == "" {
		t.Fatal("S1 requires planned owned ext4 image/private mount namespace")
	}
	ns, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || ns == hostNS {
		t.Fatal("host namespace cannot run S1 mounts", err)
	}
	marker, err := os.ReadFile(filepath.Join(image, ".sfc-storage-test-owner"))
	if err != nil || string(marker) != tag {
		t.Fatal("exact owned ext4 image marker required", err)
	}
	base, err := os.MkdirTemp(image, "fixed-app-")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixedAppNativeFixture{base: base, source: filepath.Join(base, "hdd", "data"), home: filepath.Join(root, "fixed-cli-home"), profile: filepath.Join(root, "fixed-cli.yaml"), binary: os.Getenv("SFC_TEST_CLI")}
	for _, path := range []string{filepath.Join(base, "hdd"), filepath.Join(base, "ssd"), f.source, f.home} {
		if err = os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chown(f.source, 10001, 10001); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(f.source, 0750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.source, "original"), []byte("preexisting-original"), 0600); err != nil {
		t.Fatal(err)
	}
	f.before, err = os.Stat(f.source)
	if err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", p.Cluster, r.Identity.Public, r.installation.config.Node.Listen)
	if err = os.WriteFile(f.profile, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	f.cli(t, ctx, 0, "wallet", "init")
	f.cli(t, ctx, 0, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	f.tenant = "tenant"
	for _, id := range []string{"hdd", "ssd"} {
		f.cli(t, ctx, 0, "node", "storage", "add", "node-a", id, "--path", filepath.Join(base, id), "--tenants", "tenant", "--max-volumes", "2", "--id", "add-"+id)
	}
	storageRoot := func(id string) nodestorage.Root {
		t.Helper()
		catalog, err := p.NodeStorage(read().State)
		if err != nil {
			t.Fatal(err)
		}
		v, ok := catalog.Root("node-a", id)
		if !ok {
			t.Fatal("root definition missing", id)
		}
		return v
	}
	fixedNativeWait(t, ctx, "actual root attestation", func() bool { return storageRoot("hdd").Attestation != nil && storageRoot("ssd").Attestation != nil })
	for _, id := range []string{"hdd", "ssd"} {
		f.cli(t, ctx, 0, "node", "storage", "show", "node-a", id)
	}
	space, diagnostic, err := runManagedCLICommand(ctx, f.binary, f.home, f.profile, []string{"node", "storage", "space", "node-a"}, nil)
	var pools []nodestorage.Capacity
	if err != nil || json.Unmarshal(space, &pools) != nil || len(pools) != 1 || pools[0].Roots != 2 {
		t.Log(err, string(diagnostic), string(space))
		t.Fatal("same filesystem space counted twice")
	}
	hdd := storageRoot("hdd")
	f.cli(t, ctx, 0, "volume", "register", "data", "--node", "node-a", "--storage", "hdd", "--root-generation", fmt.Sprint(hdd.Generation), "--path", f.source, "--generation", "3", "--id", "fixed-register", "--no-wait")
	fixedNativeWait(t, ctx, "actual fixed native registration", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		ready, ok := v.Native("tenant", "", "data")
		if ok {
			f.ready = ready
		}
		return ok
	})
	if f.ready.Verify() != nil || f.ready.Fixed == nil || f.ready.Spec.Scope.App != "" || f.ready.Spec.Scope.Generation != 3 || f.ready.Fixed.Path != f.source {
		t.Fatal("registered another native source")
	}
	f.cli(t, ctx, 0, "op", "show", "fixed-register")
	f.cli(t, ctx, 0, "volume", "show", "data")
	f.cli(t, ctx, -1, "volume", "register", "outside", "--node", "node-a", "--storage", "hdd", "--root-generation", fmt.Sprint(hdd.Generation), "--path", filepath.Join(base, "ssd"), "--id", "fixed-outside")
	return f
}

// This uses a real shared consumer/SFCP permit, the product Gate and native
// writer-data adapter. The test-owned DB stands in for the embedded service's
// own durable Gate checkpoint; it does not claim an E5 registry server.
func verifyEmbeddedFixedWriter(t *testing.T, ctx context.Context, r *Runtime, root string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), ready volumes.NativeReady) {
	t.Helper()
	current := func() volumes.State {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		s, ok := v.Volume(ready.Spec.Scope)
		if !ok {
			t.Fatal("original registered Volume missing")
		}
		return s
	}
	change("embedded-acquire", "acquire-volume", current().Revision(), control.VolumeAcquire{Scope: ready.Spec.Scope, Consumer: "embedded-writer", Generation: 7, Writable: true})
	shared := current().Consumers()
	if len(shared) != 1 {
		t.Fatal("embedded shared consumer missing")
	}
	consumer := shared[0]
	lease, err := r.nativeVolumes.Pin(ctx, volumes.NativeKey(ready.Spec), volumes.DataConsumerID(consumer), ready.Generation)
	if err != nil {
		t.Fatal(err)
	}
	var data *os.Root
	returned := false
	t.Cleanup(func() {
		if data != nil {
			_ = data.Close()
		}
		if !returned {
			if err := r.nativeVolumes.Return(lease); err != nil {
				t.Error("embedded original native lease", err)
			}
		}
	})
	var boot, challenge [32]byte
	if _, err = rand.Read(boot[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}
	gate, err := volumes.NewGate(ready.Spec.Scope, ready.Owner, boot)
	if err != nil {
		t.Fatal(err)
	}
	gate, request, err := gate.Request(consumer, challenge)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(request)
	reply, err := r.appCall(ctx, "volume-permit", raw)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := schema.Decode[volumes.Permit](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || permit.Request != request {
		t.Fatal("real quorum permit required", err)
	}
	gate, err = gate.Accept(permit)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(root, "embedded-writer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	save := func() {
		raw, _ := json.Marshal(gate.Checkpoint())
		if err = db.Write(map[string][]byte{"gate": raw}); err != nil {
			t.Fatal(err)
		}
	}
	save() // durable original Starting precedes even opening the data writer
	readOnly := consumer
	readOnly.Writable = false
	if opened, err := r.nativeVolumes.OpenWriterData(ctx, ready, readOnly, lease); err == nil {
		_ = opened.Close()
		t.Fatal("read-only consumer opened a writer data root")
	}
	data, err = r.nativeVolumes.OpenWriterData(ctx, ready, consumer, lease)
	if err != nil {
		t.Fatal(err)
	}
	file, err := data.OpenFile("embedded-marker", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("embedded-original")); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	if err = data.Close(); err != nil {
		t.Fatal(err)
	}
	data = nil
	gate, err = gate.SettleStart(consumer, reconcile.EffectApplied)
	if err != nil {
		t.Fatal(err)
	}
	save()
	if err = r.nativeVolumes.Return(lease); err != nil {
		t.Fatal(err)
	}
	returned = true
	proof := volumes.Gone{Scope: ready.Spec.Scope, Consumer: consumer, Stopped: true, MountsGone: true}
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.GoneBytes(proof))
	change("embedded-release", "release-volume", current().Revision(), proof)
	if len(current().Consumers()) != 0 {
		t.Fatal("embedded shared writer not returned")
	}
}

func verifyFixedAppNative(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, p control.Policy, read func() cluster.View, wait func(string, func() bool), f *fixedAppNativeFixture, checks []func()) {
	t.Helper()
	if len(checks) != 3 {
		t.Fatal("original CLI lifecycle hooks required")
	}
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	checks[0]()
	r := *runtime
	status, err := r.workload.Status(ctx, key)
	if err != nil || !status.Ready {
		t.Fatal("actual fixed Task readiness", err)
	}
	actual, err := r.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	originalSource, err := os.Open(f.source)
	if err != nil {
		t.Fatal(err)
	}
	defer originalSource.Close()
	if err = engine.CheckProcessBindSources(actual.Container.State.Pid, []engine.BindSource{{Path: "/data", DirectoryFD: int(originalSource.Fd())}}); err != nil {
		t.Fatal("actual runtime did not mount original data inode", err)
	}
	wrongSource, err := os.Open(filepath.Dir(f.source))
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.CheckProcessBindSources(actual.Container.State.Pid, []engine.BindSource{{Path: "/data", DirectoryFD: int(wrongSource.Fd())}}); err == nil {
		_ = wrongSource.Close()
		t.Fatal("runtime mount accepted another source inode")
	}
	_ = wrongSource.Close()
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	execution, ok := apps.Execution("tenant", "app")
	if !ok {
		t.Fatal("original execution missing")
	}
	stage, ok := execution.Stage(key)
	if !ok || stage.Result == nil {
		t.Fatal("original Task result missing")
	}
	ref := deployment.ObjectRef{Key: key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	bound, ok := apps.Binding(ref)
	if !ok || len(bound.Pins()) != 1 || bound.Pins()[0].Scope != f.ready.Spec.Scope {
		t.Fatal("app did not borrow original tenant Volume")
	}
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	volume, ok := registry.Volume(f.ready.Spec.Scope)
	if !ok {
		t.Fatal("registered original missing")
	}
	for _, writable := range []bool{true, false} {
		f.rejectChange(t, ctx, fmt.Sprintf("fixed-live-conflict-%t", writable), "acquire-volume", volume.Revision(), control.VolumeAcquire{Scope: f.ready.Spec.Scope, Consumer: "conflicting-user", Generation: 1, Writable: writable})
	}
	row, err := r.workload.View(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	*runtime = nil
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	*runtime = reopened
	r = reopened
	if _, err = r.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	read() // installation alone does not prove the reopened control has a quorum leader
	if err = r.workload.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	again, err := r.workload.Status(ctx, key)
	if err != nil || again.NativeID != status.NativeID || !again.Ready {
		t.Fatal("same DB replaced fixed Task/data", err)
	}
	after, err := r.workload.View(key)
	if err != nil || after.State.LastID != row.State.LastID || after.State.Applied != row.State.Applied {
		t.Fatal("same DB changed original Task operation", err)
	}
	f.cli(t, ctx, -1, "volume", "unregister", "data", "--id", "fixed-live-unregister")
	book, err := p.NodeStorage(read().State)
	if err != nil {
		t.Fatal(err)
	}
	hdd, _ := book.Root("node-a", "hdd")
	f.cli(t, ctx, -1, "node", "storage", "remove", "node-a", "hdd", "--if-revision", fmt.Sprint(hdd.Revision), "--id", "fixed-live-root-remove")
	f.cli(t, ctx, 0, "node", "storage", "set", "node-a", "hdd", "--remove-tenants", "tenant", "--if-revision", fmt.Sprint(hdd.Revision), "--id", "fixed-revoke-root")
	if _, err = r.appInputPermit(ctx, control.AppBindingRequest{Task: ref, Digest: bound.Digest()}); err == nil {
		t.Fatal("revoked root still authorized a new Task effect")
	}
	checks[1]()
	wait("fixed app original retirement", func() bool {
		a, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range a.Records() {
			if v.App == "app" && v.Retirement != nil {
				return v.Retirement.Status == "Retired"
			}
		}
		return false
	})
	checks[2]()
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	volume, ok = registry.Volume(f.ready.Spec.Scope)
	if !ok || volume.Deleted() || len(volume.Consumers()) != 0 {
		t.Fatal("app down removed registration or retained its consumer")
	}
	if gone, err := r.docker.Gone(ctx, "container", key); err != nil || !gone {
		t.Fatal("original fixed Task remains", err)
	}
	book, err = p.NodeStorage(read().State)
	if err != nil {
		t.Fatal(err)
	}
	hdd, _ = book.Root("node-a", "hdd")
	f.cli(t, ctx, 0, "node", "storage", "set", "node-a", "hdd", "--add-tenants", "tenant", "--if-revision", fmt.Sprint(hdd.Revision), "--id", "fixed-restore-root")
	verifyFixedReadOnlyApp(t, ctx, r, filepath.Dir(f.profile), p, read, f)
	f.cli(t, ctx, 0, "volume", "unregister", "data", "--id", "fixed-unregister", "--no-wait")
	fixedNativeWait(t, ctx, "fixed original non-destructive unregister", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		s, ok := v.Volume(f.ready.Spec.Scope)
		return ok && s.Deleted()
	})
	f.cli(t, ctx, 0, "op", "show", "fixed-unregister")
	for _, id := range []string{"hdd", "ssd"} {
		book, err = p.NodeStorage(read().State)
		if err != nil {
			t.Fatal(err)
		}
		root, _ := book.Root("node-a", id)
		f.cli(t, ctx, 0, "node", "storage", "drain", "node-a", id, "--if-revision", fmt.Sprint(root.Revision), "--id", "fixed-drain-"+id)
		fixedNativeWait(t, ctx, "original root closure", func() bool {
			b, err := p.NodeStorage(read().State)
			if err != nil {
				t.Fatal(err)
			}
			r, ok := b.Root("node-a", id)
			return ok && r.Closed != nil
		})
		book, err = p.NodeStorage(read().State)
		if err != nil {
			t.Fatal(err)
		}
		root, _ = book.Root("node-a", id)
		f.cli(t, ctx, 0, "node", "storage", "remove", "node-a", id, "--if-revision", fmt.Sprint(root.Revision), "--id", "fixed-remove-"+id)
	}
	last, err := os.Stat(f.source)
	if err != nil || !os.SameFile(f.before, last) || last.Mode() != f.before.Mode() {
		t.Fatal("unregister changed original directory", err)
	}
	for name, want := range map[string]string{"original": "preexisting-original", "embedded-marker": "embedded-original", "marker": "volume-original"} {
		data, err := os.ReadFile(filepath.Join(f.source, name))
		if err != nil || string(data) != want {
			t.Fatal("source data not retained", name, err)
		}
	}
	t.Log("actual CLI storage roots/one filesystem pool, registered fixed source, shared embedded writer/quorum Gate/data FD, app external source/real Docker bind, same DB/original Task, current root revocation/old down, original unregister/root closure/data retention; no registry or two-physical-node claim")
}

func verifyFixedReadOnlyApp(t *testing.T, ctx context.Context, r *Runtime, root string, p control.Policy, read func() cluster.View, f *fixedAppNativeFixture) {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(root, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	service := input.Services["web"]
	service.Volumes = append(deployment.Mounts(nil), service.Volumes...)
	service.Volumes[0].ReadOnly = true
	input.Services["web"] = service
	document, err = yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "readonly.app.yaml")
	if err = os.WriteFile(file, document, 0600); err != nil {
		t.Fatal(err)
	}
	call := func(args ...string) {
		t.Helper()
		out, diag, err := runManagedCLICommand(ctx, f.binary, filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			t.Fatal("fixed readonly app CLI", args, err, string(diag), string(out))
		}
	}
	call("compose", "up", "--tenant", "tenant", "--operation", "fixed-readonly", "-f", file, "--no-input")
	call("compose", "wait", "--tenant", "tenant", "-p", "app", "--operation", "fixed-readonly", "--condition", "healthy")
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	status, err := r.workload.Status(ctx, key)
	if err != nil || !status.Ready {
		t.Fatal("actual readonly fixed Task", err)
	}
	got, err := r.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	matches := 0
	for _, m := range got.Container.Mounts {
		if m.Destination == "/data" {
			if m.RW {
				t.Fatal("readonly source mounted writable")
			}
			matches++
		}
	}
	if matches != 1 {
		t.Fatal("readonly source mount missing")
	}
	created, err := r.docker.API.ExecCreate(ctx, status.NativeID, client.ExecCreateOptions{User: "10001:10001", Cmd: []string{"/backend", "--volume-readonly-probe"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.docker.API.ExecStart(ctx, created.ID, client.ExecStartOptions{Detach: true}); err != nil {
		t.Fatal(err)
	}
	fixedNativeWait(t, ctx, "actual read-only write refusal", func() bool {
		result, err := r.docker.API.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Running {
			return false
		}
		if result.ContainerID != status.NativeID || result.ExitCode != 0 {
			t.Fatal("readonly write did not fail with EROFS in the original container")
		}
		return true
	})
	call("compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "fixed-readonly-stop")
	call("compose", "wait", "--tenant", "tenant", "-p", "app", "--operation", "fixed-readonly-stop", "--condition", "retired")
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	volume, ok := registry.Volume(f.ready.Spec.Scope)
	if !ok || volume.Deleted() || len(volume.Consumers()) != 0 {
		t.Fatal("readonly app did not return original consumer")
	}
}
