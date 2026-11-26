// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/moby/moby/api/pkg/authconfig"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	dockerauth "github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
)

// This extends the existing real CLI/User/Raft/registry/Vault fixture. The
// builder is an explicitly prepared, installed digest; no image/toolchain is
// downloaded by the test. The root uses the existing S1 rollback baseline.
func (f *managedRegistryNative) verifyImageBuildNative(t *testing.T, ctx context.Context, owner **Runtime, root string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	if os.Getenv("MYDC_TEST_RQ6_REMAINING") == "image-content" {
		f.verifyRegistryContent(t)
		f.save()
		return
	}
	if os.Getenv("MYDC_TEST_RQ6_REMAINING") == "image-queries" {
		f.verifyManagedImageQueriesNative(t, ctx, *owner, p, read, change)
		return
	}
	r := *owner
	builder := os.Getenv("MYDC_TEST_BUILDKIT_IMAGE")
	builderImage, err := access.PinImage(builder)
	if err != nil || builderImage.Reference != builder {
		t.Fatal("explicit canonical digest-pinned BuildKit v0.35.1 rootless image required")
	}
	if _, err = r.docker.API.ImageInspect(ctx, builder); err != nil {
		t.Fatal("builder must already be installed; no implicit preparation", err)
	}
	parent, tag := os.Getenv("MYDC_STORAGE_TEST_ROOT"), os.Getenv("MYDC_STORAGE_TEST_OWNER")
	ns, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || ns == os.Getenv("MYDC_STORAGE_HOST_MOUNT_NS") {
		t.Fatal("BuildKit fixture requires the owned private mount namespace", err)
	}
	marker, err := os.ReadFile(filepath.Join(parent, ".mydc-storage-test-owner"))
	if err != nil || string(marker) != tag {
		t.Fatal("BuildKit fixture requires the exact owned ext4 root marker", err)
	}
	base, err := os.MkdirTemp(parent, "rq6-build-")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	f.public["ImageBuildRoot"], f.public["ImageBuildBuilder"] = base, builder
	f.save()
	t.Cleanup(func() {
		// The original registry callback still needs the runtime pointer to
		// capture its Volume pins. Close is idempotent; don't clear *owner.
		if *owner != nil {
			if err := (*owner).Close(); err != nil {
				t.Error("build producer did not join; retain original build root", err)
				return
			}
		}
		current, err := os.Lstat(base)
		if err != nil || !os.SameFile(original, current) || !current.IsDir() {
			t.Error("build rollback root identity changed; retain", err)
			return
		}
		if err = os.RemoveAll(base); err != nil {
			t.Error("owned build root rollback", err)
			return
		}
		if _, err = os.Lstat(base); !os.IsNotExist(err) {
			t.Error("owned build root still present after rollback", err)
			return
		}
		f.public["ImageBuildRootRollback"] = "joined-and-removed"
		f.save()
	})
	f.cli(nil, "node", "storage", "add", "node-a", "rq6-build", "--path", base, "--tenants", "tenant", "--max-volumes", "16", "--id", "rq6-build-root")
	var storage nodestorage.Root
	registryNativeWait(t, ctx, "build root native attestation", func() bool {
		catalog, err := p.NodeStorage(read().State)
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		storage, ok = catalog.Root("node-a", "rq6-build")
		return ok && storage.Attestation != nil
	})
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	change("rq6-builder-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: append(tenant.ImageSources, access.TrustRule{Registry: builderImage.Registry, Repository: builderImage.Repository})})
	policy := imagebuild.Policy{Schema: 1, Tenant: "tenant", Nodes: []imagebuild.NodeRoot{{Node: "node-a", Root: storage.Reference(p.Cluster)}}, Concurrency: 1, Seconds: 180, CPUMillis: 750, MemoryBytes: 512 << 20, WorkspaceBytes: 128 << 20, CacheBytes: 256 << 20, Registry: "private", Platforms: []string{"linux/amd64"}, BuilderImage: builder, Cleanup: imagebuild.CleanupPolicy{HighWaterPercent: 90, UnusedDays: 1}}
	change("rq6-build-policy", "set-image-build-policy", 0, control.ImageBuildPolicyPut{Spec: policy})
	spec := imagebuild.ContextSpec{Tenant: "tenant", ID: "native-build", Kind: "upload", Root: storage.Reference(p.Cluster), Dockerfile: "Dockerfile", Repository: "fixture", Tags: []string{"native-build"}, Platforms: []string{"linux/amd64"}, Secrets: []imagebuild.SecretMount{{ID: "native-secret", Realm: "tenant", Secret: "data", Key: "DB_PASSWORD"}}}
	remaining := os.Getenv("MYDC_TEST_RQ6_REMAINING")
	if remaining == "cancel-runtime" {
		f.verifyImageBuildCancelNative(t, ctx, r, root, spec, p, read, change)
		return
	}
	if remaining == "transfer-gate" {
		// Reuse only the registered root/policy setup. The helper owns its
		// small Manager context; no BuildKit solve or large ZIP follows it.
		f.verifyImageBuildTransferGateNative(t, ctx, r, root, spec, p, read, change)
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		storedPolicy, _ := book.Policy("tenant")
		change("rq6-native-delete-policy", "delete-image-build-policy", storedPolicy.Revision, control.ImageBuildSelection{Tenant: "tenant"})
		return
	}
	// The finite large-upload helper owns and retires its own context. An
	// unused default context would correctly block the final policy deletion.
	if remaining != "large-context" {
		change("rq6-build-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	}
	if remaining == "cache-runtime" {
		f.verifyImageBuildCacheRuntimeNative(t, ctx, r, root, spec, p, read, change)
		return
	}
	if remaining != "1" && remaining != "large-context" {
		const contextProof = "rq6-native-upload-context"
		secretDigest := sha256.Sum256([]byte("private-db-value"))
		dockerfile := fmt.Sprintf("FROM %s\nUSER 0:0\nCOPY --chmod=0444 context-proof /build-context-proof\nRUN --mount=type=secret,id=native-secret,required=true [\"/backend\",\"--build-secret-fixture\",\"%x\"]\nLABEL org.mydc.test.owner=%q\nUSER 10001:10001\n", f.reference, secretDigest, f.public["Tag"])
		version := f.uploadBuildNative(t, root, spec.ID, "rq6-native-upload", dockerfile, contextProof)
		password := filepath.Join(root, "build-group-password")
		if err = os.WriteFile(password, []byte("private-native-group-password"), 0600); err != nil {
			t.Fatal(err)
		}
		input, err := os.Open(password)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		const jobID = "rq6-native-build"
		f.cli([]*os.File{input}, "registry", "build", spec.ID, hex.EncodeToString(version[:]), "--tenant", "tenant", "--job", jobID, "--request-id", "rq6-native-submit", "--no-input", "--group-password-fd", "tenant/group=3")
		if err = input.Close(); err != nil {
			t.Fatal(err)
		}
		if err = os.Remove(password); err != nil {
			t.Fatal(err)
		}
		job := f.waitImageBuildNative(t, ctx, r, p, read, jobID, "OK")
		var status control.ImageBuildPage
		if err = json.Unmarshal(f.cli(nil, "registry", "build-job", jobID, "--tenant", "tenant"), &status); err != nil || len(status.Jobs) != 1 || status.Jobs[0].ID != jobID || status.Jobs[0].Result == nil || *status.Jobs[0].Result != job.Run.Closure.Result || status.Jobs[0].Phase != "succeeded" {
			t.Fatal("actual CLI build result differs from original committed closure", err)
		}
		if r.imageBuildNative == nil {
			t.Fatal("actual native builder missing")
		}
		native, err := r.imageBuildNative.Record(job.Run.Spec)
		if err != nil || native.Solve == nil || !native.Solve.Returned || native.Solve.Code != "OK" || !native.Waited || !native.Removed || native.Workspace == nil || !native.Workspace.Closed || native.Root == nil || !native.Root.Returned || native.Completion == nil || native.Completion.Result != job.Run.Closure.Result {
			t.Fatal("actual solve/daemon/workspace/root closure incomplete", err)
		}
		if _, err = r.docker.API.ContainerInspect(ctx, native.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("finite builder container survived terminal closure", err)
		}
		f.verifyImageBuildNativeLogs(t, job.Run.Spec)
		f.executeImageBuildResult(t, ctx, r, job.Run.Closure.Result.Image, "--build-result-fixture", contextProof)
		f.public["ImageBuildJob"], f.public["ImageBuildResult"] = jobID, job.Run.Closure.Result
		f.public["ImageBuildNativeClosed"], f.public["ImageBuildSecretMountAndRedaction"] = true, true
		f.save()
		// A separate declared context is rejected by the real worker's tenant
		// trust resolver before any pull. No server at this authority is started.
		untrusted := spec.Own()
		untrusted.ID, untrusted.Tags, untrusted.Secrets = "native-untrusted", []string{"native-untrusted"}, nil
		change("rq6-untrusted-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: untrusted})
		untrustedVersion := f.uploadBuildNative(t, root, untrusted.ID, "rq6-untrusted-upload", "FROM untrusted.invalid/fixture:latest\n", contextProof)
		const rejectedID = "rq6-native-untrusted"
		f.cli(nil, "registry", "build", untrusted.ID, hex.EncodeToString(untrustedVersion[:]), "--tenant", "tenant", "--job", rejectedID, "--request-id", "rq6-untrusted-submit", "--no-input")
		rejected := f.waitImageBuildNative(t, ctx, r, p, read, rejectedID, "UNTRUSTED_BASE")
		if rejected.Run.Closure.Result.Image != "" || rejected.Run.Closure.Result.Bytes != 0 {
			t.Fatal("untrusted source invented published output")
		}
		f.public["ImageBuildUntrustedSource"] = rejected.Run.Closure.Result.Code
		f.save()
		// Release references through the actual signed management core. The
		// isolated cache remains until normal product retirement or test rollback;
		// deleting a context/policy is not evidence that cache bytes disappeared.
		for _, original := range []struct {
			job, context, prefix string
			version              [32]byte
		}{{jobID, spec.ID, "rq6-native", version}, {rejectedID, untrusted.ID, "rq6-untrusted", untrustedVersion}} {
			f.cli(nil, "registry", "delete-build-job", original.job, "--tenant", "tenant", "--request-id", original.prefix+"-delete-job")
			book, err := p.ImageBuilds(read().State)
			if err != nil {
				t.Fatal(err)
			}
			storedVersion, ok := book.Version("tenant", original.version)
			if !ok {
				t.Fatal("original build version missing")
			}
			change(original.prefix+"-delete-version", "delete-build-version", storedVersion.Number, control.ImageBuildVersionSelection{Tenant: "tenant", ID: original.version})
			context, ok := book.Context("tenant", original.context)
			if !ok {
				t.Fatal("original build context missing")
			}
			change(original.prefix+"-delete-context", "delete-build-context", context.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: original.context})
		}
		// Keep the existing registry fixture's image/GC inventory independent of
		// this extra output. This is an explicit managed delete after job release.
		digest := strings.SplitN(job.Run.Closure.Result.Image, "@", 2)[1]
		f.cli(nil, "registry", "delete-image", "private", "--tenant", "tenant", "--repository", "fixture", "--reference", digest, "--expected-digest", digest, "--request-id", "rq6-native-delete-output")
		f.maintenanceNativeWait(t, ctx, p, read, "rq6-native-delete-output", "done", "OK")
		f.verifyImageBuildGitNative(t, ctx, r, root, spec, p, read, change)
		f.verifyImageBuildDraftNative(t, ctx, r, root, spec, p, read, change)
		f.verifyImageBuildFilePagesNative(t, ctx, r, root, spec, p, read, change)
	} else {
		// This explicit verifier selection does not resume/resubmit an old
		// job. The caller retains current8's successful build/Secret/Tail,
		// Git/manual+automatic/draft/file scopes as separate evidence.
		f.public["ImageBuildScope"] = "external-and-large-context"
		if remaining == "large-context" {
			f.public["ImageBuildScope"] = "large-context"
		}
		f.save()
	}
	if remaining != "large-context" {
		f.verifyImageBuildExternalNative(t, ctx, r, root, spec, p, read, change)
	}
	if os.Getenv("MYDC_TEST_RQ6_LARGE_CONTEXT") == "1" {
		f.verifyLargeImageBuildZIPNative(t, ctx, root, spec, p, read, change)
	}
	book, err := p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	storedPolicy, _ := book.Policy("tenant")
	change("rq6-native-delete-policy", "delete-image-build-policy", storedPolicy.Revision, control.ImageBuildSelection{Tenant: "tenant"})
}

func (f *managedRegistryNative) uploadBuildNative(t *testing.T, root, id, upload, dockerfile, proof string) [32]byte {
	t.Helper()
	file := filepath.Join(root, upload+".zip")
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, entry := range []struct{ path, value string }{{"Dockerfile", dockerfile}, {"context-proof", proof}} {
		out, err := writer.Create(entry.path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(out, entry.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(f.cli(nil, "registry", "upload-context", id, file, "--tenant", "tenant", "--upload-id", upload, "--request-id", upload), &response); err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(response.Version)
	if err != nil || len(decoded) != 32 {
		t.Fatal("actual CLI upload did not return a version", err)
	}
	return [32]byte(decoded)
}

func (f *managedRegistryNative) waitImageBuildNative(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, id, code string) control.ImageBuildJobRecord {
	t.Helper()
	var result control.ImageBuildJobRecord
	var previousDiagnostic string
	registryNativeWait(t, ctx, "original image build "+id, func() bool {
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		result, ok = book.Job("tenant", id)
		r.mu.Lock()
		diagnostic := fmt.Sprint(r.imageBuildError)
		r.mu.Unlock()
		// Observe the original runtime, without opening its CLI wallet or
		// submitting replacement work. Report changes rather than silently
		// waiting through the whole scenario after a worker refusal.
		if diagnostic != previousDiagnostic {
			previousDiagnostic = diagnostic
			t.Log("original build worker", id, "phase", result.Run.Phase, "diagnostic", diagnostic)
		}
		return ok && result.Run.Terminal()
	})
	if result.Run.Closure.Result.Code != code {
		t.Fatal("original image build failed", result.Run.Phase, result.Run.Closure.Result.Code)
	}
	return result
}

func (f *managedRegistryNative) verifyImageBuildNativeLogs(t *testing.T, spec imagebuild.JobSpec) {
	t.Helper()
	// Tail is the FIRST log request. No previous page/cursor was requested.
	var tail control.ImageBuildLogPage
	if err := json.Unmarshal(f.cli(nil, "registry", "build-logs", spec.ID, "--tenant", "tenant", "--tail"), &tail); err != nil || !tail.Page.Available || tail.Page.Job != spec.Digest() || tail.Page.Total < 400<<10 || tail.Page.Offset != tail.Page.Total-imagebuild.MaxLogPageBytes || len(tail.Page.Data) != imagebuild.MaxLogPageBytes || !bytes.Contains(tail.Page.Data, []byte("owned-build-tail-complete")) {
		t.Fatal("first actual log request did not read the 400KiB stream's final page", "error", err, "available", tail.Page.Available, "total", tail.Page.Total, "offset", tail.Page.Offset, "bytes", len(tail.Page.Data), "marker", bytes.Contains(tail.Page.Data, []byte("owned-build-tail-complete")))
	}
	var data bytes.Buffer
	var cursor string
	for {
		args := []string{"registry", "build-logs", spec.ID, "--tenant", "tenant"}
		if cursor != "" {
			args = append(args, "--after", cursor)
		}
		var page control.ImageBuildLogPage
		if err := json.Unmarshal(f.cli(nil, args...), &page); err != nil || !page.Page.Available || page.Page.Job != spec.Digest() || page.Page.Unclosed || page.Page.Gap || page.Page.Truncated || page.Page.Offset != uint32(data.Len()) || page.Page.Total > imagebuild.MaxLogBytes {
			t.Fatal("actual build logs incomplete or foreign", err)
		}
		data.Write(page.Page.Data)
		if page.Page.Next == page.Page.Total {
			break
		}
		if page.Next == "" || page.Next == cursor || len(page.Page.Data) == 0 {
			t.Fatal("build log cursor failed to advance")
		}
		cursor = page.Next
	}
	if bytes.Contains(data.Bytes(), []byte("private-db-value")) || !bytes.Contains(data.Bytes(), []byte("owned-build-secret=")) {
		t.Fatal("actual Secret progress was absent or not redacted")
	}
	if tail.Page.Total != uint32(data.Len()) || !bytes.Equal(tail.Page.Data, data.Bytes()[max(0, data.Len()-imagebuild.MaxLogPageBytes):]) {
		t.Fatal("actual build CLI tail differs from original stored output")
	}
	var eof control.ImageBuildLogPage
	if err := json.Unmarshal(f.cli(nil, "registry", "build-logs", spec.ID, "--tenant", "tenant", "--after", tail.Next), &eof); err != nil || eof.Page.Offset != tail.Page.Total || len(eof.Page.Data) != 0 {
		t.Fatal("actual tail cursor cannot be polled", err)
	}
}

func (f *managedRegistryNative) executeImageBuildResult(t *testing.T, ctx context.Context, r *Runtime, image string, command ...string) {
	t.Helper()
	secret := f.credential(t, "pull")
	defer clear(secret)
	auth, err := authconfig.Encode(dockerauth.AuthConfig{ServerAddress: f.address, Username: "admin", Password: string(secret)})
	if err != nil {
		t.Fatal(err)
	}
	// Record stable owned identities before sending effects; a lost create
	// response must not make the test container undiscoverable at rollback.
	containerID := "mydc-" + f.public["Tag"].(string) + "-build-proof"
	if _, err := r.docker.API.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("result fixture name must be absent before create", err)
	}
	if _, err := r.docker.API.ImageInspect(ctx, image); !cerrdefs.IsNotFound(err) {
		t.Fatal("result image must be absent before owned pull", err)
	}
	imageID := ""
	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if containerID != "" {
			got, err := r.docker.API.ContainerInspect(clean, containerID, client.ContainerInspectOptions{})
			if !cerrdefs.IsNotFound(err) {
				if err != nil || got.Container.Config == nil || got.Container.Config.Image != image || got.Container.Config.Labels["org.mydc.test.owner"] != f.public["Tag"] {
					t.Error("result container ownership changed; retain", err)
					return
				}
				if _, err = r.docker.API.ContainerRemove(clean, containerID, client.ContainerRemoveOptions{Force: true}); err != nil {
					t.Error("exact result container rollback", err)
					return
				}
			}
		}
		got, err := r.docker.API.ImageInspect(clean, image)
		if cerrdefs.IsNotFound(err) {
			cleaned = true
			return
		}
		if err != nil || imageID != "" && got.ID != imageID || got.Config == nil || got.Config.Labels["org.mydc.test.owner"] != f.public["Tag"] {
			t.Error("result image identity changed; retain", err)
			return
		}
		if _, err = r.docker.API.ImageRemove(clean, image, client.ImageRemoveOptions{}); err != nil && !cerrdefs.IsNotFound(err) {
			t.Error("exact result image rollback", err)
			return
		}
		cleaned = true
	}
	t.Cleanup(cleanup)
	pull, err := r.docker.API.ImagePull(ctx, image, client.ImagePullOptions{RegistryAuth: auth})
	if err != nil {
		t.Fatal("result digest actual authenticated pull", err)
	}
	err = pull.Wait(ctx)
	closeErr := pull.Close()
	if err != nil || closeErr != nil {
		t.Fatal("result pull stream failed", err, closeErr)
	}
	inspected, err := r.docker.API.ImageInspect(ctx, image)
	if err != nil || inspected.Config == nil || inspected.Config.Labels["org.mydc.test.owner"] != f.public["Tag"] {
		t.Fatal("actual build result image ownership", err)
	}
	imageID = inspected.ID
	created, err := r.docker.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: containerID, Config: &container.Config{Image: image, Entrypoint: []string{"/backend"}, Cmd: command, Labels: map[string]string{"org.mydc.test.owner": f.public["Tag"].(string)}}, HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Resources: container.Resources{NanoCPUs: 100_000_000, Memory: 32 << 20}}})
	if err != nil {
		t.Fatal("result fixture create", err)
	}
	containerID = created.ID
	f.public["ImageBuildResultContainer"] = containerID
	f.save()
	if _, err = r.docker.API.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		t.Fatal("result fixture start", err)
	}
	wait := r.docker.API.ContainerWait(ctx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case <-ctx.Done():
		t.Fatal("result fixture did not exit", ctx.Err())
	case err := <-wait.Error:
		t.Fatal("result wait failed", err)
	case exit := <-wait.Result:
		if exit.StatusCode != 0 {
			t.Fatal("result command failed", exit.StatusCode)
		}
	}
	logs, err := r.docker.API.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "16"})
	if err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	_, err = stdcopy.StdCopy(&out, &diagnostic, io.LimitReader(logs, 4097))
	closeErr = logs.Close()
	if err != nil || closeErr != nil || out.String() != "owned-build-result-ok\n" || diagnostic.Len() != 0 {
		t.Fatal("result did not verify actual context/Secret mount/non-persistence", err, closeErr)
	}
	cleanup()
	if !cleaned {
		t.Fatal("result resources did not settle before managed deletion")
	}
}
