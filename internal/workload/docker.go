// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"log"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	"github.com/moby/moby/api/types/container"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

type ContainerSpec struct {
	Ports            []PublishedPort                `json:",omitempty"`
	Writable         bool                           `json:",omitempty"`
	TTY              bool                           `json:",omitempty"`
	StdinOpen        bool                           `json:",omitempty"`
	ResourceKeys     []lifecycle.IdentityTransition `json:",omitempty"`
	BridgeOwner      string                         `json:",omitempty"`
	Schema           uint8
	Node, Image      string
	Pull             bool
	Command, Env     []string
	Bridge           string
	BridgeGeneration uint64
	IPv4, IPv6       netip.Addr
	Memory, NanoCPU  int64
	Lifecycle        schema.Lifecycle
	Process          *Process      `json:",omitempty"`
	Inputs           *InputRef     `json:",omitempty"`
	Tmpfs            []Tmpfs       `json:",omitempty"`
	Volumes          []VolumeMount `json:",omitempty"`
	// RemoteVolumes are shared Volumes whose home is another server.
	RemoteVolumes []RemoteVolumeMount `json:",omitempty"`
	Readiness     *HTTPReadiness      `json:",omitempty"`
	Routes        []ContainerRoute    `json:",omitempty"`
	Resolver      *Resolver           `json:",omitempty"`
	Stop          *engine.StopPolicy  `json:",omitempty"`
	Logging       *LogPolicy          `json:",omitempty"`
}

func DecodeContainer(value string) (ContainerSpec, error) {
	s, err := schema.Decode[ContainerSpec]([]byte(value))
	if err != nil || s.Schema != 1 || s.Node == "" || s.Bridge == "" || s.BridgeGeneration == 0 || s.Memory < 16<<20 || s.NanoCPU <= 0 || s.Process == nil && len(s.Command) == 0 || len(s.Command) > 128 || len(s.Env) > 128 || !s.Lifecycle.Valid() {
		return s, ErrPlacement
	}
	if s.Process != nil && (s.Command != nil || s.Env != nil || s.Process.Validate() != nil) {
		return s, ErrPlacement
	}
	if ValidatePublishedPorts(s.Ports) != nil {
		return s, ErrPublishedPorts
	}
	if s.Logging != nil && s.Logging.Validate() != nil {
		return s, ErrLogPolicy
	}
	if s.Stop != nil && (s.Process == nil || s.Stop.Validate() != nil) {
		return s, engine.ErrStopPolicy
	}
	if _, err = engine.StopPolicyFromSpec(value); err != nil {
		return s, err
	}
	if len(s.Tmpfs) > 0 && (s.Process == nil || ValidateTmpfs(s.Tmpfs, s.Memory, nil) != nil) {
		return s, ErrPlacement
	}
	if s.Inputs != nil && (s.Process == nil || !strings.HasPrefix(s.Inputs.Key, "workload/inputs/") || len(s.Inputs.Key) > 512 || strings.ContainsRune(s.Inputs.Key, 0) || s.Inputs.Generation == 0 || s.Inputs.Binding == ([32]byte{})) {
		return s, ErrPlacement
	}
	if !s.validBridgeOwner() || validateVolumeMounts(s) != nil || validateRemoteVolumes(s) != nil {
		return s, ErrVolumeMount
	}
	if s.Readiness != nil && (s.Process == nil || !s.Readiness.Valid()) {
		return s, ErrProcess
	}
	if validateContainerRoutes(s, nil) != nil {
		return s, ErrPlacement
	}
	if s.Resolver != nil && s.Resolver.Validate() != nil {
		return s, ErrPlacement
	}
	// A mutable tag cannot silently change the executable on another node or
	// after restart. An image ID or repository digest is explicit Desired.
	r, err := reference.ParseAnyReference(s.Image)
	if err != nil {
		return s, ErrPlacement
	}
	if _, ok := r.(reference.Digested); !ok {
		return s, ErrPlacement
	}
	if !s.IPv4.IsValid() && !s.IPv6.IsValid() || s.IPv4.IsValid() && (!s.IPv4.Is4() || s.IPv4.IsUnspecified() || s.IPv4.IsMulticast()) || s.IPv6.IsValid() && (!s.IPv6.Is6() || s.IPv6.Is4In6() || s.IPv6.Zone() != "" || s.IPv6.IsUnspecified() || s.IPv6.IsMulticast()) {
		return s, ErrPlacement
	}
	for _, v := range append(append([]string(nil), s.Command...), s.Env...) {
		if strings.ContainsRune(v, 0) {
			return s, ErrPlacement
		}
	}
	return s, nil
}

type DockerDriver struct {
	Engine         *engine.Client
	Network        BridgeProvider
	Inputs         InputProvider
	Volumes        *volumes.Activations
	Remote         RemoteVolumes // nil: tasks with remote Volumes are refused
	Authority      TaskAuthority
	ImageAuthority TaskImageAuthority
	// These belong to one Manager.Step invocation; never shared across actors.
	startCheckpoint *reconcile.EffectCheckpoint
	saveStart       func([]byte) error
}

// TaskAuthority checks current app admission immediately before a new Create
// or stopped Start. Running observation and original Remove do not use it.
type TaskAuthority func(context.Context, string, reconcile.Operation) error

// TaskImageAuthority obtains fresh, original Task-scoped pull input before even
// a cached image is inspected. Credentials are never saved in the journal.
type TaskImageAuthority func(context.Context, string, reconcile.Operation) (engine.RegistryAuth, error)

type BridgeProvider interface {
	Acquire(context.Context, string, string, uint64) (network.BridgeLease, error)
	InspectConsumer(context.Context, string, string, uint64) (network.BridgeLease, error)
	ReturnConsumer(string, string, uint64) error
}

func (d *DockerDriver) parameters(key string, op reconcile.Operation) (ContainerSpec, engine.Identity, error) {
	s, err := DecodeContainer(op.Target.Spec)
	if err != nil || d.Engine == nil || d.Network == nil || d.taskNetworkManager(s) == nil || s.Node != d.Engine.Owner || s.Inputs != nil && s.Inputs.Generation != op.Target.Generation {
		return s, engine.Identity{}, engine.ErrOwnership
	}
	if len(s.Volumes) > 0 {
		if d.Volumes == nil || !d.Volumes.UsesClient(d.Engine) {
			return s, engine.Identity{}, ErrVolumeMount
		}
		if _, err = volumeReferences(s, key, op); err != nil {
			return s, engine.Identity{}, err
		}
	}
	if len(s.RemoteVolumes) > 0 && d.Remote == nil {
		return s, engine.Identity{}, ErrVolumeMount
	}
	id, err := d.Engine.Identity("container", key, op.Target)
	return s, id, err
}
func containerConsumer(id engine.Identity) string { return "workload/" + id.Name }

func (d *DockerDriver) options(ctx context.Context, s ContainerSpec, id engine.Identity, key string, generation uint64) (client.ContainerCreateOptions, error) {
	l, err := d.taskNetworkManager(s).Acquire(ctx, s.Bridge, containerConsumer(id), s.BridgeGeneration)
	if err != nil {
		return client.ContainerCreateOptions{}, err
	}
	for _, address := range []netip.Addr{s.IPv4, s.IPv6} {
		if !address.IsValid() {
			continue
		}
		allowed := false
		for _, p := range l.Spec.Pools {
			if p.Prefix.Contains(address) && address != p.Gateway && address != p.Prefix.Addr() && (!address.Is4() || p.Prefix.Contains(address.Next())) {
				allowed = true
			}
		}
		if !allowed {
			return client.ContainerCreateOptions{}, network.ErrPolicy
		}
	}
	if err = ValidateContainerRoutes(s, l.Spec); err != nil {
		return client.ContainerCreateOptions{}, err
	}
	ipam := &dockernet.EndpointIPAMConfig{}
	if s.IPv4.IsValid() {
		ipam.IPv4Address = s.IPv4
	}
	if s.IPv6.IsValid() {
		ipam.IPv6Address = s.IPv6
	}
	config := &container.Config{Image: s.Image, Cmd: s.Command, Env: s.Env, Labels: id.Labels}
	if s.Process != nil {
		config, err = s.Process.ContainerConfig(id.Labels)
		if err != nil {
			return client.ContainerCreateOptions{}, err
		}
	}
	if s.Stop != nil {
		grace := s.Stop.GraceSeconds
		config.StopTimeout = &grace
	}
	inputs, err := d.inputLease(ctx, s, id, key, generation, "acquire")
	if err != nil {
		return client.ContainerCreateOptions{}, err
	}
	config.Env, err = inputEnvironment(ctx, config.Env, inputs.Files)
	if err != nil {
		return client.ContainerCreateOptions{}, err
	}
	var targets []string
	for _, v := range s.Volumes {
		targets = append(targets, v.Target)
	}
	for _, f := range inputs.Files {
		if f.Kind == "env" {
			continue
		}
		for _, target := range targets {
			if OverlappingMounts(target, f.Target) {
				return client.ContainerCreateOptions{}, ErrVolumeMount
			}
		}
		targets = append(targets, f.Target)
	}
	if ValidateTmpfs(s.Tmpfs, s.Memory, targets) != nil {
		return client.ContainerCreateOptions{}, ErrTmpfs
	}
	volumeMounts, err := d.specMounts(s)
	if err != nil {
		return client.ContainerCreateOptions{}, err
	}
	mounts := append(inputMounts(inputs.Files), volumeMounts...)
	exposed, published, err := nativePublishedPorts(s.Ports)
	if err != nil {
		return client.ContainerCreateOptions{}, err
	}
	config.ExposedPorts = exposed
	config.Tty, config.OpenStdin = s.TTY, s.StdinOpen
	host := &container.HostConfig{Mounts: mounts, Tmpfs: tmpfsMounts(s.Tmpfs), NetworkMode: container.NetworkMode(l.NetworkID), ReadonlyRootfs: !s.Writable, RestartPolicy: container.RestartPolicy{Name: "no"}, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, Resources: container.Resources{Memory: s.Memory, NanoCPUs: s.NanoCPU}}
	host.PortBindings = published
	if s.Logging != nil {
		if err := s.Logging.Validate(); err != nil {
			return client.ContainerCreateOptions{}, err
		}
		host.LogConfig = s.Logging.Native()
	}
	if s.Resolver != nil {
		host.DNS = slices.Clone(s.Resolver.Servers)
		host.DNSSearch = slices.Clone(s.Resolver.Search)
	}
	return client.ContainerCreateOptions{Name: id.Name, Config: config, HostConfig: host, NetworkingConfig: &dockernet.NetworkingConfig{EndpointsConfig: map[string]*dockernet.EndpointSettings{l.NetworkID: {IPAMConfig: ipam}}}}, nil
}

func (d *DockerDriver) matchContainer(ctx context.Context, got container.InspectResponse, s ContainerSpec, id engine.Identity, l network.BridgeLease, files []InputFile) bool {
	volumeMounts, err := d.specMounts(s)
	if err != nil {
		return false
	}
	networkID := l.NetworkID
	image, command, env := s.Image, s.Command, s.Env
	if s.Process != nil {
		image, command, env = s.Process.ImageID, s.Process.Command, s.Process.Env
		env, err = inputEnvironment(ctx, env, files)
		if err != nil {
			return false
		}
		if got.Config == nil || got.HostConfig == nil || got.Image != image || got.Config.User != s.Process.User || got.Config.WorkingDir != s.Process.WorkingDir || !slices.Equal(got.Config.Entrypoint, s.Process.Entrypoint) || !slices.Equal(got.Config.Cmd, command) || !slices.Equal(got.Config.Env, env) || !reflect.DeepEqual(got.Config.Healthcheck, s.Process.Healthcheck) || got.Config.StopSignal != s.Process.StopSignal || len(got.HostConfig.CapAdd) != 0 || len(got.HostConfig.CapDrop) != 1 || got.HostConfig.CapDrop[0] != "ALL" || len(got.HostConfig.SecurityOpt) != 1 || got.HostConfig.SecurityOpt[0] != "no-new-privileges" && got.HostConfig.SecurityOpt[0] != "no-new-privileges:true" {
			return false
		}
	} else if got.Config != nil && (!reflect.DeepEqual(got.Config.Cmd, command) || !reflect.DeepEqual(got.Config.Env, env)) {
		return false
	}
	if got.Config == nil || got.HostConfig == nil || got.State == nil || got.NetworkSettings == nil || !id.Matches(got.Name, got.Config.Labels) || got.ID == "" || got.Config.Image != image || got.HostConfig.Memory != s.Memory || got.HostConfig.NanoCPUs != s.NanoCPU || got.HostConfig.ReadonlyRootfs == s.Writable || got.Config.Tty != s.TTY || got.Config.OpenStdin != s.StdinOpen || got.HostConfig.Privileged || got.HostConfig.NetworkMode != container.NetworkMode(networkID) || len(got.HostConfig.Binds) != 0 || !matchResolvedTaskMounts(got, files, len(s.Volumes)+len(s.RemoteVolumes), volumeMounts) || !matchTmpfs(got, s.Tmpfs) {
		return false
	}
	if !matchPublishedPorts(s.Ports, got) {
		return false
	}
	if !s.Logging.Matches(got.HostConfig.LogConfig) {
		return false
	}
	raw, _ := json.Marshal(s)
	if _, err = engine.MatchStopPolicy(string(raw), got.Config); err != nil {
		return false
	}
	if got.HostConfig.RestartPolicy.Name != "" && got.HostConfig.RestartPolicy.Name != "no" || got.HostConfig.RestartPolicy.MaximumRetryCount != 0 || got.HostConfig.AutoRemove {
		return false
	}
	if len(got.NetworkSettings.Networks) != 1 {
		return false
	}
	if s.Resolver != nil && (!slices.Equal(got.HostConfig.DNS, s.Resolver.Servers) || !slices.Equal(got.HostConfig.DNSSearch, s.Resolver.Search)) {
		return false
	}
	for name, e := range got.NetworkSettings.Networks {
		if name != l.NetworkName || e.IPAMConfig == nil || e.NetworkID != "" && e.NetworkID != networkID || got.State.Running && e.NetworkID != networkID {
			return false
		}
		if e.IPAMConfig.IPv4Address != s.IPv4 || e.IPAMConfig.IPv6Address != s.IPv6 || got.State.Running && (s.IPv4.IsValid() && e.IPAddress != s.IPv4 || s.IPv6.IsValid() && e.GlobalIPv6Address != s.IPv6) {
			return false
		}
	}
	return true
}

func (d *DockerDriver) dependency(ctx context.Context, s ContainerSpec, id engine.Identity) (network.BridgeLease, error) {
	return d.taskNetworkManager(s).Acquire(ctx, s.Bridge, containerConsumer(id), s.BridgeGeneration)
}

func (d *DockerDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	s, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	_, err = d.Engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if err != nil && !cerrdefs.IsNotFound(err) {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		// Normal removal needs the original durable receipt supplied by Journal.
		return reconcile.EffectUnknown, reconcile.ErrOperation
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, reconcile.ErrOperation
	}
	if cerrdefs.IsNotFound(err) {
		options, optionErr := d.options(ctx, s, id, key, op.Target.Generation)
		if optionErr != nil {
			// Execute alone knows create has not been called. Recover must not
			// infer this from a later absence after a persisted dispatch.
			return d.beforeCreateFailed(ctx, s, id, key, op, optionErr)
		}
		var auth engine.RegistryAuth
		if d.ImageAuthority != nil {
			auth, err = d.ImageAuthority(ctx, key, op)
			if err != nil {
				return d.beforeCreateFailed(ctx, s, id, key, op, err)
			}
		} else if d.Authority != nil {
			if err = d.Authority(ctx, key, op); err != nil {
				return d.beforeCreateFailed(ctx, s, id, key, op, err)
			}
		}
		image, imageErr := d.Engine.ImageWithAuth(ctx, s.Image, s.Pull, auth)
		if imageErr != nil {
			return d.beforeCreateFailed(ctx, s, id, key, op, imageErr)
		}
		var targets []string
		for _, m := range options.HostConfig.Mounts {
			targets = append(targets, m.Target)
		}
		for target := range options.HostConfig.Tmpfs {
			targets = append(targets, target)
		}
		if image.Config == nil || CheckImageMounts(image.Config.Volumes, targets) != nil || s.Process != nil && image.ID != s.Process.ImageID {
			return d.beforeCreateFailed(ctx, s, id, key, op, ErrProcess)
		}
		var secretTargets []string
		inputs, inputErr := d.inputLease(ctx, s, id, key, op.Target.Generation, "inspect")
		if inputErr != nil {
			return d.beforeCreateFailed(ctx, s, id, key, op, inputErr)
		}
		for _, f := range mountedInputFiles(inputs.Files) {
			secretTargets = append(secretTargets, f.Target)
		}
		if CheckSecretImageMounts(image.Config.Volumes, secretTargets) != nil {
			return d.beforeCreateFailed(ctx, s, id, key, op, ErrInputMount)
		}
		if err = ctx.Err(); err != nil {
			return d.beforeCreateFailed(ctx, s, id, key, op, err)
		}
		if d.Authority != nil {
			if err = d.Authority(ctx, key, op); err != nil {
				return d.beforeCreateFailed(ctx, s, id, key, op, err)
			}
		}
		// Remote Volumes are mounted here first; the engine's Mount answer
		// for the new container needs them.
		if err = d.holdRemote(ctx, s); err != nil {
			return d.beforeCreateFailed(ctx, s, id, key, op, err)
		}
		if len(s.Volumes) > 0 {
			refs, refErr := volumeReferences(s, key, op)
			if refErr != nil {
				return reconcile.EffectUnknown, refErr
			}
			if err = d.Volumes.PrepareCreateAll(ctx, refs); err != nil {
				return d.beforeCreateFailed(ctx, s, id, key, op, err)
			}
			if err = ctx.Err(); err != nil {
				return reconcile.EffectUnknown, err
			}
			if err = d.Volumes.CreateAll(ctx, refs, options); err != nil {
				return reconcile.EffectUnknown, err
			}
		} else {
			if _, err = d.Engine.API.ContainerCreate(ctx, options); err != nil {
				return reconcile.EffectUnknown, err
			}
		}
	}
	return d.Recover(ctx, key, op)
}

// Only the fresh Execute branch calls this, before ContainerCreate. No native
// container can use this attempt's dependency pin, so settle that dependency
// before publishing NotApplied. A failed return remains Unknown and keeps the
// original operation instead of forgetting an orphaned dependency.
func (d *DockerDriver) beforeCreateFailed(ctx context.Context, s ContainerSpec, id engine.Identity, key string, op reconcile.Operation, cause error) (reconcile.Outcome, error) {
	if len(s.Volumes) > 0 {
		if d.Volumes == nil {
			return reconcile.EffectUnknown, errors.Join(cause, ErrVolumeMount)
		}
		refs, err := volumeReferences(s, key, op)
		if err != nil {
			return reconcile.EffectUnknown, errors.Join(cause, err)
		}
		unprepared, err := d.Volumes.CreateUnpreparedAll(refs)
		if err == nil && unprepared {
			if _, err := d.releaseDependencies(ctx, s, id, key, op.Target.Generation); err != nil {
				return reconcile.EffectUnknown, errors.Join(cause, err)
			}
			return reconcile.EffectNotApplied, cause
		}
		prepared, err := d.preparedVolumes(s, key, op)
		if prepared || err != nil {
			return reconcile.EffectUnknown, errors.Join(cause, err)
		}
	}
	if _, err := d.releaseDependencies(ctx, s, id, key, op.Target.Generation); err != nil {
		return reconcile.EffectUnknown, errors.Join(cause, err)
	}
	return reconcile.EffectNotApplied, cause
}

func (d *DockerDriver) release(ctx context.Context, s ContainerSpec, id engine.Identity, key string, generation uint64) (reconcile.Outcome, error) {
	return d.releaseDependencies(ctx, s, id, key, generation)
}

func (d *DockerDriver) releaseDependencies(_ context.Context, s ContainerSpec, id engine.Identity, key string, generation uint64) (reconcile.Outcome, error) {
	consumer := containerConsumer(id)
	if err := d.taskNetworkManager(s).ReturnConsumer(s.Bridge, consumer, s.BridgeGeneration); err != nil {
		return reconcile.EffectUnknown, err
	}
	if s.Inputs != nil {
		if d.Inputs == nil {
			return reconcile.EffectUnknown, ErrInputMount
		}
		if err := d.Inputs.ReturnInputs(*s.Inputs, consumer, key, generation); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	return reconcile.EffectApplied, nil
}

func (d *DockerDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	s, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	got, err := d.Engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if op.Kind == reconcile.Remove {
			// Inspect found no container: its remote mounts may go.
			if e := d.releaseRemote(s); e != nil {
				return reconcile.EffectUnknown, e
			}
			if e := d.retireVolumes(ctx, s, key, op); e != nil {
				return reconcile.EffectUnknown, e
			}
			return d.release(ctx, s, id, key, op.Target.Generation)
		}
		if len(s.Volumes) > 0 {
			if d.Volumes == nil {
				return reconcile.EffectUnknown, ErrVolumeMount
			}
			refs, refErr := volumeReferences(s, key, op)
			if refErr != nil {
				return reconcile.EffectUnknown, refErr
			}
			unprepared, proofErr := d.Volumes.CreateUnpreparedAll(refs)
			if proofErr == nil && unprepared {
				if _, err := d.releaseDependencies(ctx, s, id, key, op.Target.Generation); err != nil {
					return reconcile.EffectUnknown, err
				}
				return reconcile.EffectNotApplied, nil
			}
			prepared, e := d.preparedVolumes(s, key, op)
			if e != nil {
				return reconcile.EffectUnknown, e
			}
			if prepared {
				return d.Execute(ctx, key, op)
			}
		}
		return reconcile.EffectUnknown, nil
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	var l network.BridgeLease
	exited := engine.ObserveContainerExit(got.Container.State) != nil
	if got.Container.State != nil && got.Container.State.Running || exited || op.Kind == reconcile.Remove {
		l, err = d.taskNetworkManager(s).InspectConsumer(ctx, s.Bridge, containerConsumer(id), s.BridgeGeneration)
	} else {
		l, err = d.dependency(ctx, s, id)
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	mode := "inspect"
	if op.Kind == reconcile.Remove {
		mode = "retire"
	} else if got.Container.State != nil && !got.Container.State.Running && !exited {
		mode = "acquire"
	}
	inputs, inputErr := d.inputLease(ctx, s, id, key, op.Target.Generation, mode)
	if inputErr != nil {
		return reconcile.EffectUnknown, inputErr
	}
	if !d.matchContainer(ctx, got.Container, s, id, l, inputs.Files) {
		return reconcile.EffectUnknown, engine.ErrOwnership
	}
	if op.Kind == reconcile.Remove {
		return reconcile.EffectUnknown, nil
	}
	if err = d.bindRemote(s, got.Container.ID); err != nil {
		return reconcile.EffectUnknown, err
	}
	if got.Container.State.Running || exited {
		// Positive evidence that an earlier Start ran.
		if err = d.endRemoteStart(s); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	if len(s.Volumes) == 0 {
		if err = d.startIdentity(op, got.Container.ID); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	if !got.Container.State.Running && !exited && !engine.ContainerStartable(got.Container.State) {
		return reconcile.EffectUnknown, reconcile.ErrPending
	}
	if !got.Container.State.Running && !exited && d.Authority != nil {
		if err = d.Authority(ctx, key, op); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	if !got.Container.State.Running && !exited {
		// Journaled before the Start; an unknown outcome stays recorded.
		if err = d.beginRemoteStart(s); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	if len(s.Volumes) > 0 {
		refs, e := d.originalVolumes(s, key, op)
		if e != nil {
			return reconcile.EffectUnknown, e
		}
		if e = d.Volumes.ActivateAll(ctx, refs); e != nil {
			return reconcile.EffectUnknown, e
		}
		got, err = d.Engine.API.ContainerInspect(ctx, got.Container.ID, client.ContainerInspectOptions{})
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		if !d.matchContainer(ctx, got.Container, s, id, l, inputs.Files) {
			return reconcile.EffectUnknown, engine.ErrOwnership
		}
	}
	if engine.ObserveContainerExit(got.Container.State) != nil {
		// The ORIGINAL Start has happened, even if it finished before an
		// inspect or its reply was lost. Default restart=no never runs it twice.
		// This settles Apply only; success/dependencies require signed exit0,
		// and all network/input/Volume pins remain until explicit retirement.
		return reconcile.EffectApplied, nil
	}
	if !got.Container.State.Running && len(s.Volumes) == 0 {
		// Only the fresh A2 call can sync this original Start witness. A
		// restored Created state cannot prove a previous Start did not run.
		if err = d.dispatchStart(op, got.Container.ID); err != nil {
			return reconcile.EffectUnknown, err
		}
		if err = ctx.Err(); err != nil {
			return reconcile.EffectUnknown, err
		}
		if _, err = d.Engine.API.ContainerStart(ctx, got.Container.ID, client.ContainerStartOptions{}); err != nil {
			return reconcile.EffectUnknown, err
		}
		got, err = d.Engine.API.ContainerInspect(ctx, got.Container.ID, client.ContainerInspectOptions{})
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		if !d.matchContainer(ctx, got.Container, s, id, l, inputs.Files) {
			return reconcile.EffectUnknown, engine.ErrOwnership
		}
	}
	if got.Container.State.Running || engine.ObserveContainerExit(got.Container.State) != nil {
		if err = d.endRemoteStart(s); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	if !got.Container.State.Running && engine.ObserveContainerExit(got.Container.State) != nil {
		return reconcile.EffectApplied, nil
	}
	if !got.Container.State.Running {
		return reconcile.EffectUnknown, errors.New("container is not running after start")
	}
	ready, routeErr := containerRoutes(ctx, s, l.Spec, got.Container, false)
	if routeErr != nil {
		return reconcile.EffectUnknown, routeErr
	}
	if !ready {
		if d.Authority != nil {
			if err = d.Authority(ctx, key, op); err != nil {
				return reconcile.EffectUnknown, err
			}
		}
		ready, routeErr = containerRoutes(ctx, s, l.Spec, got.Container, true)
		if routeErr != nil || !ready {
			return reconcile.EffectUnknown, errors.Join(routeErr, engine.ErrOwnership)
		}
		fresh, e := d.Engine.API.ContainerInspect(ctx, got.Container.ID, client.ContainerInspectOptions{})
		if e != nil {
			return reconcile.EffectUnknown, e
		}
		if !d.matchContainer(ctx, fresh.Container, s, id, l, inputs.Files) || fresh.Container.State.Pid != got.Container.State.Pid || fresh.Container.NetworkSettings.SandboxID != got.Container.NetworkSettings.SandboxID || fresh.Container.NetworkSettings.SandboxKey != got.Container.NetworkSettings.SandboxKey {
			return reconcile.EffectUnknown, engine.ErrOwnership
		}
	}
	return reconcile.EffectApplied, nil
}

type Manager struct {
	controlMu sync.Mutex // serialize lifecycle effects with Desired/Step
	journal   *reconcile.Journal
	driver    *DockerDriver
	logs      LogReader
}

func OpenManager(path string, c *engine.Client, n BridgeProvider) (*Manager, error) {
	return OpenManagerWithInputs(path, c, n, nil)
}
func OpenManagerWithInputs(path string, c *engine.Client, n BridgeProvider, inputs InputProvider) (*Manager, error) {
	return OpenManagerWithResources(path, c, n, inputs, nil)
}
func OpenManagerWithResources(path string, c *engine.Client, n BridgeProvider, inputs InputProvider, activation *volumes.Activations, authorities ...TaskAuthority) (*Manager, error) {
	if len(authorities) > 1 {
		return nil, ErrPlacement
	}
	if activation != nil && !activation.UsesClient(c) {
		return nil, ErrVolumeMount
	}
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	driver := &DockerDriver{Engine: c, Network: n, Inputs: inputs, Volumes: activation}
	if len(authorities) == 1 {
		driver.Authority = authorities[0]
	}
	return &Manager{journal: j, driver: driver}, nil
}

// OpenManagerWithImageAuthority wires managed Task auth at construction; no
// mutable global Engine auth or runtime setter is needed.
func OpenManagerWithImageAuthority(path string, c *engine.Client, n BridgeProvider, inputs InputProvider, activation *volumes.Activations, authority TaskAuthority, images TaskImageAuthority) (*Manager, error) {
	if authority == nil || images == nil {
		return nil, ErrPlacement
	}
	m, err := OpenManagerWithResources(path, c, n, inputs, activation, authority)
	if err != nil {
		return nil, err
	}
	m.driver.ImageAuthority = images
	return m, nil
}

// AttachRemoteVolumes is Runtime assembly, before the module loop runs any
// Step: the runner journal of remote shared Volumes (remote.Mounts).
func (m *Manager) AttachRemoteVolumes(r RemoteVolumes) error {
	if r == nil || m.driver.Remote != nil {
		return ErrPlacement
	}
	m.driver.Remote = r
	return nil
}
func (m *Manager) Desired(key string, revision, generation uint64, s *ContainerSpec, capacity int) error {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	d := reconcile.Desired{Revision: revision}
	if s == nil {
		d.Retiring = generation
	}
	if s != nil {
		if s.Inputs != nil && (m.driver.Inputs == nil || s.Inputs.Generation != generation) {
			return ErrInputMount
		}
		if len(s.Volumes) > 0 {
			if m.driver.Volumes == nil || m.driver.Engine == nil || s.Node != m.driver.Engine.Owner {
				return ErrVolumeMount
			}
			for _, v := range s.Volumes {
				if v.Consumer.Generation != generation {
					return ErrVolumeMount
				}
			}
		}
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		if _, err = DecodeContainer(string(b)); err != nil {
			return err
		}
		d.Resource = reconcile.Resource{Generation: generation, Spec: string(b), Present: true}
		if _, err = volumeReferences(*s, key, reconcile.Operation{ID: 1, Target: d.Resource}); err != nil {
			return err
		}
	}
	return m.journal.Desired(key, d, capacity)
}
func (m *Manager) Step(ctx context.Context, key string) error {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	before, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	driver := *m.driver
	driver.startCheckpoint = before.Checkpoint
	if err := m.journal.Step(ctx, key, &driver); err != nil {
		return err
	}
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	if r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return nil
	}
	// Applied records the original creation/start. Maintenance keeps terminal
	// originals under restart=no and never dispatches another create.
	driver = *m.driver
	driver.startCheckpoint = r.Checkpoint
	outcome, err := driver.Recover(ctx, key, reconcile.Operation{ID: r.State.LastID, Kind: reconcile.Apply, Target: r.State.Applied, Phase: reconcile.Dispatched})
	if err != nil {
		return err
	}
	if outcome != reconcile.EffectApplied {
		return reconcile.ErrPending
	}
	return nil
}
func (m *Manager) View(key string) (reconcile.Record, error) { return m.journal.Read(key) }
func (m *Manager) Keys() []string                            { return m.journal.Keys() }
func (m *Manager) Gone(ctx context.Context, key string, revision, generation uint64) (bool, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return false, err
	}
	if generation == 0 || revision == 0 || r.State.GenerationFloor != generation || r.State.Desired.Revision < revision || r.State.Pending != nil || r.State.Applied.Present || r.State.Desired.Present || len(r.Consumers) != 0 {
		return false, nil
	}
	return m.driver.Engine.Gone(ctx, "container", key)
}
func (m *Manager) Inspect(ctx context.Context, key string) (string, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return "", err
	}
	if r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return "", reconcile.ErrPending
	}
	status, err := m.Status(ctx, key)
	if err == nil && !status.Ready {
		err = errors.New("container is not ready")
	}
	return status.NativeID, err
}

type ContainerStatus struct {
	ProcessReady                     bool                   `json:",omitempty"`
	TaskFact                         *containerops.TaskFact `json:",omitempty"`
	LogDriver                        string                 `json:",omitempty"`
	NativeID                         string
	StartedAt                        string `json:",omitempty"`
	Startable                        bool   `json:",omitempty"`
	Running, HealthConfigured, Ready bool
	Health                           string
	HTTPConfigured, HTTPReady        bool                  `json:",omitempty"`
	Exit                             *engine.ContainerExit `json:",omitempty"`
}

// Running is an Engine process fact; Ready also requires that the process can
// execute. A paused container can retain a stale healthy healthcheck result.
func containerProcessReady(s *container.State) bool {
	return s != nil && s.Running && !s.Paused && !s.Restarting && !s.Dead
}

// Observe reads an original Applied object, including a draining consumer. It
// neither acquires new pins nor restarts a stopped container.
func (m *Manager) Observe(ctx context.Context, key string) (string, bool, error) {
	status, err := m.Status(ctx, key)
	return status.NativeID, status.Running, err
}

// Status verifies the original native identity and reads readiness without
// restarting the process, acquiring a new pin or exposing healthcheck output.
func (m *Manager) Status(ctx context.Context, key string) (ContainerStatus, error) {
	return m.status(ctx, key, true)
}

// NativeIdentity verifies the same original journal/spec, running native ID,
// input/Volume references and Bridge/routes as Status, without executing an
// application readiness probe. Infrastructure consumed by readiness (DNS in
// particular) must not recursively invoke that probe to admit its own client.
func (m *Manager) NativeIdentity(ctx context.Context, key string) (string, bool, error) {
	started := time.Now()
	status, err := m.status(ctx, key, false)
	if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
		log.Printf("native identity slow: elapsed=%s failed=%t", elapsed, err != nil)
	}
	return status.NativeID, status.Running, err
}

// NetworkIdentity proves the original container for an allocated endpoint.
// Mount identities still match the original spec, but Volume availability is
// not packet provenance. All workload/Volume consumers keep their full checks.
func (m *Manager) NetworkIdentity(ctx context.Context, key string, generation uint64) (string, bool, error) {
	if ctx == nil || generation == 0 {
		return "", false, ErrPlacement
	}
	before, err := m.journal.Read(key)
	if err != nil {
		return "", false, err
	}
	if before.State.Pending != nil || !before.State.Applied.Present || before.State.Applied.Generation != generation {
		return "", false, reconcile.ErrPending
	}
	status, err := m.statusRecord(ctx, key, before, false, false, true)
	if err != nil {
		return "", false, err
	}
	after, err := m.journal.Read(key)
	if err != nil || !sameProbeTask(before, after) || ctx.Err() != nil {
		return "", false, errors.Join(reconcile.ErrPending, err, ctx.Err())
	}
	return status.NativeID, status.Running, nil
}

func (m *Manager) status(ctx context.Context, key string, probe bool) (ContainerStatus, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return ContainerStatus{}, err
	}
	if r.State.Pending != nil || !r.State.Applied.Present {
		return ContainerStatus{}, reconcile.ErrPending
	}
	return m.statusRecord(ctx, key, r, probe, true, true)
}

func (m *Manager) statusRecord(ctx context.Context, key string, r reconcile.Record, probe, inspectVolumes, inspectRoutes bool) (ContainerStatus, error) {
	started := time.Now()
	stage := "parameters"
	var networkTime, containerTime, inputTime, routeTime, volumeTime time.Duration
	if !probe && inspectVolumes && inspectRoutes {
		defer func() {
			if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
				log.Printf("native identity stages: elapsed=%s network=%s container=%s inputs=%s routes=%s volumes=%s stage=%s", elapsed, networkTime, containerTime, inputTime, routeTime, volumeTime, stage)
			}
		}()
	}
	if !r.State.Applied.Present {
		return ContainerStatus{}, reconcile.ErrPending
	}
	op := reconcile.Operation{Kind: reconcile.Apply, Target: r.State.Applied}
	s, id, err := m.driver.parameters(key, op)
	if err != nil {
		return ContainerStatus{}, err
	}
	stage = "network"
	at := time.Now()
	bridge := m.driver.taskNetworkManager(s)
	if bridge == nil {
		return ContainerStatus{}, engine.ErrOwnership
	}
	l, err := bridge.InspectConsumer(ctx, s.Bridge, containerConsumer(id), s.BridgeGeneration)
	networkTime = time.Since(at)
	if err != nil {
		return ContainerStatus{}, err
	}
	stage = "container"
	at = time.Now()
	got, err := m.driver.Engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	containerTime = time.Since(at)
	if err != nil {
		return ContainerStatus{}, err
	}
	stage = "inputs"
	at = time.Now()
	inputs, inputErr := m.driver.inputLease(ctx, s, id, key, op.Target.Generation, "inspect")
	inputTime = time.Since(at)
	if inputErr != nil {
		return ContainerStatus{}, inputErr
	}
	if !m.driver.matchContainer(ctx, got.Container, s, id, l, inputs.Files) {
		return ContainerStatus{}, engine.ErrOwnership
	}
	if got.Container.State.Running && inspectRoutes {
		stage = "routes"
		at = time.Now()
		ready, e := containerRoutes(ctx, s, l.Spec, got.Container, false)
		routeTime = time.Since(at)
		if e != nil || !ready {
			return ContainerStatus{}, errors.Join(e, engine.ErrOwnership)
		}
	}
	if len(s.Volumes) > 0 && inspectVolumes {
		stage = "volumes"
		at = time.Now()
		refs, err := m.driver.originalVolumes(s, key, op)
		if err != nil {
			return ContainerStatus{}, err
		}
		err = m.driver.Volumes.InspectAll(ctx, refs, got.Container.ID)
		volumeTime = time.Since(at)
		if err != nil {
			return ContainerStatus{}, err
		}
	}
	status := ContainerStatus{NativeID: got.Container.ID, Running: got.Container.State.Running, Health: "disabled"}
	status.LogDriver = got.Container.HostConfig.LogConfig.Type
	stage = "complete"
	fact := containerops.TaskFact{Name: strings.TrimPrefix(got.Container.Name, "/"), Image: got.Container.Image, State: "unknown"}
	// matchContainer already proved the one original network attachment. The
	// endpoint's own inspected IDs, independently of process Running, prove
	// whether that attachment currently has a native endpoint.
	endpointPresent := false
	for _, endpoint := range got.Container.NetworkSettings.Networks {
		endpointPresent = endpoint.EndpointID != "" && endpoint.NetworkID == l.NetworkID
	}
	fact.EndpointPresent = &endpointPresent
	if got.Container.RestartCount >= 0 {
		fact.RestartCount = uint64(got.Container.RestartCount)
	}
	state := got.Container.State
	if state.Restarting {
		fact.State = "restarting"
	} else if state.Running {
		fact.State = "running"
	} else if state.Status == container.StateExited || state.Dead {
		fact.State = "exited"
	}
	if state.Health != nil && len(state.Health.Log) > 0 {
		last := state.Health.Log[len(state.Health.Log)-1]
		if last.End.Unix() > 0 {
			result := "fail"
			if last.ExitCode == 0 {
				result = "pass"
			}
			fact.LastCheck = &containerops.TaskCheck{Checker: "docker-health", Status: result, At: uint64(last.End.Unix())}
		}
	}
	status.TaskFact = &fact
	status.StartedAt = got.Container.State.StartedAt
	status.Startable = engine.ContainerStartable(state) || !state.Running && !state.Paused && !state.Restarting && !state.Dead && state.Pid == 0 && state.Error == "" && state.Status == container.StateExited
	status.Exit = engine.ObserveContainerExit(got.Container.State)
	status.ProcessReady = containerProcessReady(state)
	status.Ready = status.ProcessReady
	if s.Process != nil && s.Process.Healthcheck != nil && len(s.Process.Healthcheck.Test) > 0 && s.Process.Healthcheck.Test[0] != "NONE" {
		status.HealthConfigured = true
		status.Health = "unknown"
		if got.Container.State.Health != nil {
			status.Health = string(got.Container.State.Health.Status)
		}
		status.Ready = status.Ready && status.Health == "healthy"
	}
	if s.Readiness != nil {
		status.HTTPConfigured = true
		status.HTTPReady = probe && containerProcessReady(state) && httpReady(ctx, s)
		status.Ready = status.Ready && status.HTTPReady
	}
	return status, nil
}
func (m *Manager) Close() error {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	return m.journal.Close()
}
