// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/hex"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// NativePlan fixes Engine-owned identities. All paths are derived from the
// registered root, never supplied by app input. NativeJobs checks their saved
// inode/FDs through the existing guarded Engine transport before mutation.
type NativePlan struct {
	Job, Cache [32]byte
	Container  engine.Identity
}

const nativeBuilderUID = 1000

func nativeWorkspaceNames(p NativePlan) [3]string {
	job := ".mydc-imagebuild/jobs/" + hex.EncodeToString(p.Job[:])
	return [3]string{job + "/input", job + "/output", ".mydc-imagebuild/build-cache/" + hex.EncodeToString(p.Cache[:])}
}
func nativeWorkspacePaths(spec JobSpec, p NativePlan) [3]string {
	names := nativeWorkspaceNames(p)
	return [3]string{filepath.Join(spec.Scope.Root.Path, names[0]), filepath.Join(spec.Scope.Root.Path, names[1]), filepath.Join(spec.Scope.Root.Path, names[2])}
}

// All shell text is product code. Tenant Dockerfile ARGs remain separate argv
// entries, never shell substitutions. The absolute accepted deadline also
// bounds a builder left running by a daemon crash; restarting the node does
// not grant a fresh execution window. BusyBox is part of the pinned Alpine
// rootless builder, and the upstream daemonless script handles its children.
const nativeDeadlineCommand = `left=$(($1 - $(/bin/busybox date +%s))); [ "$left" -gt 0 ] || exit 124; shift; exec /bin/busybox timeout -s TERM -k 10 "$left" "$@"`

func PlanNative(spec JobSpec, owner string) (NativePlan, error) {
	if spec.Validate() != nil || owner != engine.Owner(spec.Cluster, spec.Scope.Root.Key) {
		return NativePlan{}, ErrInvalid
	}
	api := engine.Client{Owner: owner}
	key := "image-build/" + spec.Tenant + "/" + spec.ID
	p := NativePlan{Job: spec.Digest()}
	var err error
	p.Container, err = api.IdentityDigest("container", key, 1, p.Job)
	if err != nil {
		return NativePlan{}, ErrInvalid
	}
	// One native cache per context/root/builder, reused only under the runtime's
	// exclusive cache borrow. Parallel daemons may never share its state DB.
	p.Cache = CacheIdentity(spec)
	return p, nil
}

// CacheIdentity is shared by native ownership and read projections. It does
// not include the job ID: successive jobs reuse exactly this cache scope.
func CacheIdentity(spec JobSpec) [32]byte {
	return digestJSON("mydc-imagebuild-cache-scope-1", struct {
		Tenant, Context, Builder string
		Root                     [32]byte
	}{spec.Tenant, spec.Context.ID, spec.Policy.BuilderImage, spec.Scope.Root.Digest()})
}

func BuildArguments(spec JobSpec) ([]string, error) {
	if spec.Validate() != nil {
		return nil, ErrInvalid
	}
	args := []string{"build", "--frontend", "dockerfile.v0", "--local", "context=/input/context", "--local", "dockerfile=/input/context", "--opt", "filename=" + spec.Scope.Dockerfile, "--opt", "platform=" + strings.Join(spec.Context.Platforms, ","), "--source-policy-file", "/input/source-policy.json", "--progress", "plain", "--metadata-file", "/output/metadata.json", "--output", "type=oci,dest=/output/image,tar=false"}
	keys := make([]string, 0, len(spec.Context.Arguments))
	for key := range spec.Context.Arguments {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		args = append(args, "--opt", "build-arg:"+key+"="+spec.Context.Arguments[key])
	}
	for _, secret := range spec.Context.Secrets {
		args = append(args, "--secret", "id="+secret.ID+",src=/input/secrets/"+secret.ID)
	}
	return args, nil
}

// CreateOptions uses the pinned upstream rootless image and its finite
// daemonless entrypoint. Only the engine-owned, registered-root directories
// are mounted. Host networking/socket, arbitrary paths, devices, extra BuildKit
// entitlements and restart loops are never added here.
func (p NativePlan) CreateOptions(spec JobSpec) (client.ContainerCreateOptions, error) {
	return p.createOptions(spec, false)
}

func (p NativePlan) createOptions(spec JobSpec, sdk bool) (client.ContainerCreateOptions, error) {
	return p.createOptionsWithTLS(spec, sdk, false)
}

func (p NativePlan) createOptionsWithTLS(spec JobSpec, sdk, tls bool) (client.ContainerCreateOptions, error) {
	want, err := PlanNative(spec, engine.Owner(spec.Cluster, spec.Scope.Root.Key))
	if err != nil || p.Job != want.Job || p.Container.Name != want.Container.Name || p.Cache != want.Cache || !maps.Equal(p.Container.Labels, want.Container.Labels) {
		return client.ContainerCreateOptions{}, ErrInvalid
	}
	args, err := BuildArguments(spec)
	if err != nil {
		return client.ContainerCreateOptions{}, err
	}
	pids := int64(512)
	stop := 10
	config := &container.Config{Image: spec.Policy.BuilderImage, User: "1000:1000", WorkingDir: "/input/context", Entrypoint: []string{"/bin/sh", "-ec", nativeDeadlineCommand, "mydc-build", strconv.FormatUint(spec.CreatedAt+spec.Policy.Seconds, 10), "/usr/bin/buildctl-daemonless.sh"}, Cmd: args, Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/home/user", "USER=user", "XDG_RUNTIME_DIR=/run/user/1000", "TMPDIR=/tmp", "BUILDKIT_HOST=unix:///run/user/1000/buildkit/buildkitd.sock", "BUILDKITD_FLAGS=--oci-worker-snapshotter=native --containerd-worker=false --root /home/user/.local/share/buildkit"}, Labels: maps.Clone(p.Container.Labels), StopSignal: "SIGTERM", StopTimeout: &stop, Healthcheck: &container.HealthConfig{Test: []string{"NONE"}}}
	if sdk {
		config.Entrypoint[len(config.Entrypoint)-1] = "/usr/bin/rootlesskit"
		config.Cmd = []string{"/usr/bin/buildkitd", "--addr", "unix:///output/buildkit.sock", "--oci-worker-snapshotter=native", "--containerd-worker=false", "--root", "/home/user/.local/share/buildkit"}
		if tls {
			config.Cmd = append(config.Cmd, "--config", "/input/buildkitd.toml")
		}
	}
	// The pinned upstream rootless mode needs user-namespace/mount syscalls and
	// an unmasked private proc mount. These are per-container SDK settings;
	// they do not alter host sysctls/profiles or enable privileged/host PID.
	paths := nativeWorkspacePaths(spec, p)
	host := &container.HostConfig{NetworkMode: "bridge", IpcMode: "none", ReadonlyRootfs: true, SecurityOpt: []string{"seccomp=unconfined", "apparmor=unconfined"}, MaskedPaths: []string{}, ReadonlyPaths: []string{}, RestartPolicy: container.RestartPolicy{Name: "no"}, LogConfig: container.LogConfig{Type: "none"}, Resources: container.Resources{Memory: spec.Policy.MemoryBytes, MemorySwap: spec.Policy.MemoryBytes, NanoCPUs: int64(spec.Policy.CPUMillis) * 1_000_000, PidsLimit: &pids}, Mounts: []mount.Mount{{Type: mount.TypeBind, Source: paths[0], Target: "/input", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}}, {Type: mount.TypeBind, Source: paths[1], Target: "/output", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}}, {Type: mount.TypeBind, Source: paths[2], Target: "/home/user/.local/share/buildkit", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}}}, Tmpfs: map[string]string{"/tmp": "rw,nosuid,nodev,exec,uid=1000,gid=1000,mode=0700,size=" + strconv.FormatInt(spec.Policy.WorkspaceBytes, 10), "/run/user/1000": "rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=0700,size=1048576"}}
	// Docker's API expresses unmasked proc paths with explicit empty lists.
	// Nil selects daemon defaults; systempaths is not a Docker SecurityOpt.
	if host.NanoCPUs <= 0 {
		return client.ContainerCreateOptions{}, fmt.Errorf("%w: cpu budget", ErrInvalid)
	}
	return client.ContainerCreateOptions{Name: p.Container.Name, Config: config, HostConfig: host}, nil
}
