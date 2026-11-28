// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// ObserveContainerDetail verifies immutable ownership without demanding native
// config equality: inequality is exactly what this read-only drift view shows.
// It grants no Start/Gone/Volume-fence fact and performs no corrective effect.
func (m *Manager) ObserveContainerDetail(ctx context.Context, target containerops.Target, q containerops.Query, declaration containerops.DetailDeclaration) (containerops.Result, error) {
	var out containerops.Result
	if m == nil || m.driver == nil || m.driver.Engine == nil || ctx == nil || q.Validate() != nil || q.Kind != "inspect" || q.Cursor != "" || !target.Valid() || m.driver.Engine.Owner != engine.Owner(target.Cluster, target.Owner) {
		return out, engine.ErrOwnership
	}
	inspection, err := m.inspectDetailNative(ctx, target)
	if err != nil {
		return out, err
	}
	before, spec, id, actual, resolved, observedAt := inspection.record, inspection.spec, inspection.id, inspection.native, inspection.target, inspection.at
	inputs, err := m.driver.inputLease(ctx, spec, id, target.Instance, target.Generation, "inspect")
	if err != nil {
		return out, err
	}
	expectedEnv := spec.Env
	if spec.Process != nil {
		expectedEnv = spec.Process.Env
	}
	expectedEnv, err = inputEnvironment(ctx, expectedEnv, inputs.Files)
	if err != nil {
		return out, err
	}
	values, err := m.logRedactionValues(ctx, target)
	if err != nil {
		return out, err
	}
	defer destroyLogValues(values)
	filter, err := containerops.NewRedactor(io.Discard, values)
	if err != nil {
		return out, err
	}
	defer filter.Destroy()
	if !m.driver.attachmentOwners(spec) {
		return out, engine.ErrOwnership
	}
	leases, bridgeErr := m.driver.inspectNetworks(ctx, spec, id)
	allowed := map[string]bool{}
	for _, lease := range leases {
		allowed[lease.NetworkID] = true
	}
	mounts, mountErr := m.driver.specMounts(spec)
	detail, err := containerDetail(spec, id, actual, inputs.Files, mounts, allowed, expectedEnv, declaration, filter)
	if err != nil {
		return out, err
	}
	networks := spec.Networks()
	if bridgeErr != nil || len(leases) != len(networks) || actual.HostConfig.NetworkMode != container.NetworkMode(leases[0].NetworkID) || len(actual.NetworkSettings.Networks) != len(networks) {
		detail.Drift = append(detail.Drift, "network")
	} else {
		for i, a := range networks {
			endpoint := taskEndpoint(actual.NetworkSettings, leases[i])
			exists := endpoint != nil
			if !exists || endpoint == nil || endpoint.NetworkID != leases[i].NetworkID || a.IPv4.IsValid() && endpoint.IPAddress != a.IPv4 || a.IPv6.IsValid() && endpoint.GlobalIPv6Address != a.IPv6 {
				detail.Drift = append(detail.Drift, "network")
				break
			}
		}
	}
	if mountErr != nil || !matchResolvedTaskMounts(actual, inputs.Files, len(spec.Volumes)+len(spec.RemoteVolumes), mounts) || !matchTmpfs(actual, spec.Tmpfs) {
		detail.Drift = append(detail.Drift, "mounts")
	}
	limit := q.HistoryLimit
	if limit == 0 {
		limit = 20
	}
	if len(detail.Checks) > limit {
		detail.Checks = detail.Checks[len(detail.Checks)-limit:]
	}
	for i := range detail.Checks {
		detail.Checks[i].Generation = target.Generation
		detail.Checks[i].Revision = target.Revision
	}
	slices.Sort(detail.Drift)
	detail.Drift = slices.Compact(detail.Drift)
	after, err := m.journal.Read(target.Instance)
	if err != nil || !sameProbeTask(before, after) {
		return out, reconcile.ErrPending
	}
	out = containerops.Result{Schema: 1, Kind: "inspect", Target: resolved, ObservedAt: observedAt, LogDriver: actual.HostConfig.LogConfig.Type, TTY: actual.Config.Tty, Detail: &detail}
	encoded, encodeErr := json.Marshal(detail)
	if encodeErr != nil {
		return containerops.Result{}, encodeErr
	}
	if len(encoded) > containerops.MaxDetailWindowBytes {
		out.Detail = nil
		return out, containerops.ErrLogWindowLimit
	}
	if err = out.ValidateDetailWindow(q, target); err != nil {
		return containerops.Result{}, err
	}
	return out, nil
}

// containerDetail is the reusable native-to-public projection used by the
// actual owner and fault tests. Raw Inspect, host paths and env values never
// cross this boundary. All free native text passes the same Secret filter.
func containerDetail(s ContainerSpec, id engine.Identity, got container.InspectResponse, files []InputFile, volumeMounts []mount.Mount, allowedNetworks map[string]bool, expectedEnv []string, decl containerops.DetailDeclaration, filter *containerops.Redactor) (containerops.ContainerDetail, error) {
	var d containerops.ContainerDetail
	if got.Config == nil || got.HostConfig == nil || got.State == nil || got.NetworkSettings == nil || filter == nil {
		return d, engine.ErrOwnership
	}
	c, h, state := got.Config, got.HostConfig, got.State
	d = containerops.ContainerDetail{Name: strings.TrimPrefix(got.Name, "/"), ImageReference: s.Image, NativeImage: c.Image, ImageID: got.Image, Command: slices.Clone(c.Cmd), Entrypoint: slices.Clone(c.Entrypoint), WorkingDir: c.WorkingDir, User: c.User, ReadOnlyRootFS: h.ReadonlyRootfs, Privileged: h.Privileged, CapabilitiesAdded: slices.Clone(h.CapAdd), CapabilitiesDropped: slices.Clone(h.CapDrop), SecurityOptions: slices.Clone(h.SecurityOpt), MemoryBytes: h.Memory, NanoCPUs: h.NanoCPUs, StopSignal: c.StopSignal, StopGraceSeconds: 10, LogDriver: h.LogConfig.Type, LogOptions: map[string]string{}, DNSSearch: slices.Clone(h.DNSSearch), Running: state.Running, Paused: state.Paused, Restarting: state.Restarting, OOMKilled: state.OOMKilled, ExitCode: state.ExitCode, StartedAt: state.StartedAt, FinishedAt: state.FinishedAt, DeclaredNetworkAliases: maps.Clone(decl.NetworkAliases), DeclaredIngress: slices.Clone(decl.Ingress)}
	for _, address := range h.DNS {
		d.DNS = append(d.DNS, address.String())
	}
	for name, aliases := range d.DeclaredNetworkAliases {
		d.DeclaredNetworkAliases[name] = slices.Clone(aliases)
	}
	for i := range d.DeclaredIngress {
		d.DeclaredIngress[i].Listeners = slices.Clone(d.DeclaredIngress[i].Listeners)
	}
	if c.StopTimeout != nil {
		d.StopGraceSeconds = *c.StopTimeout
	}
	drift := func(changed bool, field string) {
		if changed {
			d.Drift = append(d.Drift, field)
		}
	}
	drift(d.Name != id.Name, "name")
	drift(h.ReadonlyRootfs == s.Writable, "read_only_rootfs")
	drift(h.Privileged, "privileged")
	drift(h.Memory != s.Memory, "memory")
	drift(h.NanoCPUs != s.NanoCPU, "cpus")
	drift(len(h.CapAdd) != 0 || !slices.Equal(h.CapDrop, []string{"ALL"}), "capabilities")
	drift(len(h.SecurityOpt) != 1 || h.SecurityOpt[0] != "no-new-privileges" && h.SecurityOpt[0] != "no-new-privileges:true", "security_options")
	if s.Process != nil {
		drift(got.Image != s.Process.ImageID || c.Image != s.Process.ImageID, "image")
		drift(!slices.Equal(c.Cmd, s.Process.Command), "command")
		drift(!slices.Equal(c.Entrypoint, s.Process.Entrypoint), "entrypoint")
		drift(c.User != s.Process.User, "user")
		drift(c.WorkingDir != s.Process.WorkingDir, "working_dir")
		drift(!reflect.DeepEqual(c.Healthcheck, s.Process.Healthcheck), "healthcheck")
	} else {
		drift(c.Image != s.Image, "image")
		drift(!slices.Equal(c.Cmd, s.Command), "command")
	}
	raw, _ := json.Marshal(s)
	_, stopErr := engine.MatchStopPolicy(string(raw), c)
	drift(stopErr != nil, "stop_policy")
	drift(!s.Logging.Matches(h.LogConfig), "logging")
	for _, key := range []string{"max-size", "max-file", "compress"} {
		if value, ok := h.LogConfig.Config[key]; ok {
			policy := LogPolicy{Driver: "local", Options: map[string]string{key: value}}
			if policy.Validate() == nil {
				d.LogOptions[key] = value
			} else {
				drift(true, "logging")
			}
		}
	}
	actualEnv, wantEnv := map[string]string{}, map[string]string{}
	for _, raw := range c.Env {
		name, value, ok := strings.Cut(raw, "=")
		if !ok || !environmentKey(name) {
			drift(true, "environment")
			continue
		}
		if _, dup := actualEnv[name]; dup {
			drift(true, "environment")
		}
		actualEnv[name] = value
	}
	for _, raw := range expectedEnv {
		name, value, _ := strings.Cut(raw, "=")
		wantEnv[name] = value
	}
	envFiles := map[string]InputFile{}
	for _, f := range files {
		if f.Kind == "env" {
			envFiles[f.Target] = f
		}
	}
	names := map[string]bool{}
	for name := range actualEnv {
		names[name] = true
	}
	for name := range wantEnv {
		names[name] = true
	}
	keys := slices.Sorted(maps.Keys(names))
	for _, name := range keys {
		actual, present := actualEnv[name]
		wanted, expected := wantEnv[name]
		e := containerops.DetailEnvironment{Name: name, Source: "native-only", Present: present, Drift: !present || !expected || actual != wanted}
		if file, secret := envFiles[name]; secret {
			e.Source = "secret"
			e.SecretReference = file.Reference
			if e.SecretReference == "" {
				e.SecretReference = "secret/" + name
			}
		} else if literal, ok := decl.Environment[name]; ok {
			e.Source = "literal"
			if present && actual == literal {
				value := literal
				e.Value = &value
			}
		} else if expected {
			e.Source = "image"
		}
		d.Environment = append(d.Environment, e)
		drift(e.Drift, "environment")
	}
	for _, nativeMount := range got.Mounts {
		m := containerops.DetailMount{Kind: "native-only", Target: nativeMount.Destination, ReadOnly: !nativeMount.RW}
		for _, file := range files {
			if file.Kind != "env" && nativeMount.Destination == file.Target && nativeMount.Source == file.Source {
				m.Kind = "secret"
				m.Name = file.Reference
				uid, gid, mode := file.UID, file.GID, file.Mode
				m.UID, m.GID, m.Mode = &uid, &gid, &mode
			}
		}
		for _, volume := range s.Volumes {
			if nativeMount.Destination == volume.Target {
				for _, want := range volumeMounts {
					if want.Target == nativeMount.Destination && (want.Type == mount.TypeVolume && nativeMount.Name == want.Source || want.Type == mount.TypeBind && nativeMount.Source == want.Source) {
						m.Kind = "volume"
						m.Name = volume.Scope.ID
					}
				}
			}
		}
		d.Mounts = append(d.Mounts, m)
	}
	for target, options := range h.Tmpfs {
		m := containerops.DetailMount{Kind: "tmpfs", Target: target, ReadOnly: slices.Contains(strings.Split(options, ","), "ro")}
		for _, want := range s.Tmpfs {
			if want.Target == target && tmpfsMounts([]Tmpfs{want})[target] == options {
				uid, gid, mode := want.UID, want.GID, want.Mode
				m.UID, m.GID, m.Mode = &uid, &gid, &mode
			}
		}
		d.Mounts = append(d.Mounts, m)
	}
	slices.SortFunc(d.Mounts, func(a, b containerops.DetailMount) int { return strings.Compare(a.Target, b.Target) })
	for _, name := range slices.Sorted(maps.Keys(got.NetworkSettings.Networks)) {
		n := got.NetworkSettings.Networks[name]
		if n == nil {
			drift(true, "network")
			continue
		}
		if n.NetworkID == "" || !allowedNetworks[n.NetworkID] {
			d.NetworksOmitted++
			continue
		}
		d.Networks = append(d.Networks, containerops.DetailNetwork{Name: name, NativeID: n.NetworkID, IPv4: detailAddress(n.IPAddress), IPv6: detailAddress(n.GlobalIPv6Address), Aliases: slices.Clone(n.Aliases)})
	}
	if s.Resolver != nil {
		drift(!slices.Equal(h.DNS, s.Resolver.Servers) || !slices.Equal(h.DNSSearch, s.Resolver.Search), "dns")
	}
	seenPorts := map[string]bool{}
	for port, bindings := range got.NetworkSettings.Ports {
		seenPorts[port.String()] = true
		if len(bindings) == 0 {
			d.Ports = append(d.Ports, containerops.DetailPort{Port: port.Num(), Protocol: string(port.Proto())})
		}
		for _, binding := range bindings {
			d.Ports = append(d.Ports, containerops.DetailPort{Port: port.Num(), Protocol: string(port.Proto()), HostIP: detailAddress(binding.HostIP), HostPort: binding.HostPort})
		}

	}
	drift(!matchPublishedPorts(s.Ports, got), "ports")
	for port := range c.ExposedPorts {
		if !seenPorts[port.String()] {
			d.Ports = append(d.Ports, containerops.DetailPort{Port: port.Num(), Protocol: string(port.Proto())})
		}
	}
	slices.SortFunc(d.Ports, func(a, b containerops.DetailPort) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return strings.Compare(string(left), string(right))
	})
	if state.Health != nil {
		for at, health := range state.Health.Log {
			if at < max(0, len(state.Health.Log)-20) {
				continue
			}
			if health == nil {
				continue
			}
			status, message := "fail", "health command exited with nonzero status"
			if health.ExitCode == 0 {
				status, message = "pass", "health command completed"
			}
			var failures *uint32
			if at == len(state.Health.Log)-1 {
				count := uint32(min(max(0, state.Health.FailingStreak), int(^uint32(0))))
				failures = &count
			}
			d.Checks = append(d.Checks, containerops.DetailCheck{Checker: "docker-health", Phase: "liveness", Status: status, At: health.End.UTC(), DurationMS: max(0, health.End.Sub(health.Start).Milliseconds()), Message: message, ConsecutiveFailures: failures, NativeID: got.ID})
		}
	}
	if err := redactContainerDetail(&d, filter); err != nil {
		return containerops.ContainerDetail{}, err
	}
	slices.Sort(d.Drift)
	d.Drift = slices.Compact(d.Drift)
	return d, nil
}

func redactContainerDetail(d *containerops.ContainerDetail, filter *containerops.Redactor) error {
	var fields []*string
	fields = append(fields, &d.Name, &d.ImageReference, &d.NativeImage, &d.ImageID, &d.WorkingDir, &d.User, &d.StopSignal)
	for _, values := range [][]string{d.Command, d.Entrypoint, d.CapabilitiesAdded, d.CapabilitiesDropped, d.SecurityOptions, d.DNS, d.DNSSearch} {
		for i := range values {
			fields = append(fields, &values[i])
		}
	}
	for i := range d.Environment {
		e := &d.Environment[i]
		fields = append(fields, &e.Name)
		if e.Value != nil {
			fields = append(fields, e.Value)
		}
	}
	for i := range d.Mounts {
		fields = append(fields, &d.Mounts[i].Target)
	}
	for i := range d.Networks {
		n := &d.Networks[i]
		fields = append(fields, &n.Name)
		for j := range n.Aliases {
			fields = append(fields, &n.Aliases[j])
		}
	}
	for i := range d.Ports {
		fields = append(fields, &d.Ports[i].HostPort, &d.Ports[i].Protocol)
	}
	for _, field := range fields {
		value, err := filter.RedactString(*field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

func detailAddress(address netip.Addr) string {
	if address.IsValid() {
		return address.String()
	}
	return ""
}

type detailInspection struct {
	record reconcile.Record
	spec   ContainerSpec
	id     engine.Identity
	native container.InspectResponse
	target containerops.Target
	at     time.Time
}

func (m *Manager) inspectDetailNative(ctx context.Context, target containerops.Target) (detailInspection, error) {
	if m == nil || m.driver == nil || m.driver.Engine == nil || ctx == nil || !target.Valid() || m.driver.Engine.Owner != engine.Owner(target.Cluster, target.Owner) {
		return detailInspection{}, engine.ErrOwnership
	}
	before, err := m.journal.Read(target.Instance)
	if err != nil {
		return detailInspection{}, err
	}
	spec, err := probeTaskRecord(before, target.Generation, target.Revision)
	if err != nil {
		return detailInspection{}, err
	}
	_, id, err := m.driver.parameters(target.Instance, reconcile.Operation{Kind: reconcile.Apply, Target: before.State.Applied})
	if err != nil {
		return detailInspection{}, err
	}
	native := target.NativeID
	if native == "" {
		native = id.Name
	}
	observedAt := time.Now().UTC()
	got, err := m.driver.Engine.API.ContainerInspect(ctx, native, client.ContainerInspectOptions{})
	if err != nil {
		return detailInspection{}, err
	}
	actual := got.Container
	if actual.Config == nil || actual.HostConfig == nil || actual.State == nil || actual.NetworkSettings == nil || actual.ID == "" || target.NativeID != "" && actual.ID != target.NativeID || !id.Matches(id.Name, actual.Config.Labels) || target.NativeID == "" && !id.Matches(actual.Name, actual.Config.Labels) {
		return detailInspection{}, engine.ErrOwnership
	}
	resolved := target
	resolved.NativeID, resolved.StartedAt = actual.ID, actual.State.StartedAt
	if !resolved.Matches(target) {
		return detailInspection{}, engine.ErrOwnership
	}
	return detailInspection{record: before, spec: spec, id: id, native: actual, target: resolved, at: observedAt}, nil
}

// ContainerDetailIdentity checks the original native without requiring config
// equality or rebuilding a large snapshot for each continuation page.
func (m *Manager) ContainerDetailIdentity(ctx context.Context, target containerops.Target) (containerops.Target, string, error) {
	inspection, err := m.inspectDetailNative(ctx, target)
	if err != nil {
		return containerops.Target{}, "", err
	}
	after, err := m.journal.Read(target.Instance)
	if err != nil || !sameProbeTask(inspection.record, after) {
		return containerops.Target{}, "", reconcile.ErrPending
	}
	driver := inspection.native.HostConfig.LogConfig.Type
	if !containerops.ValidLogDriver(driver) {
		return containerops.Target{}, "", engine.ErrOwnership
	}
	return inspection.target, driver, nil
}
