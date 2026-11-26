// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/moby/moby/api/types/mount"
)

func TestNativeBuildPlanUsesFixedRootlessFiniteSDKOptionsAndOwnedDirectories(t *testing.T) {
	spec, _ := testJobSpec(t)
	spec.Context.Arguments["SHELL_TEXT"] = "$(touch /not-a-command); echo literal"
	spec.Context.Secrets = []SecretMount{{ID: "signing", Realm: "tenant", Secret: "key", Key: "private"}}
	plan, err := PlanNative(spec, engine.Owner(spec.Cluster, spec.Scope.Root.Key))
	if err != nil {
		t.Fatal(err)
	}
	options, err := plan.CreateOptions(spec)
	if err != nil {
		t.Fatal(err)
	}
	c, h := options.Config, options.HostConfig
	if !slices.Equal(h.SecurityOpt, []string{"seccomp=unconfined", "apparmor=unconfined"}) || h.MaskedPaths == nil || len(h.MaskedPaths) != 0 || h.ReadonlyPaths == nil || len(h.ReadonlyPaths) != 0 {
		t.Fatal("rootless proc settings must use Docker's explicit path lists")
	}
	if c.Image != spec.Policy.BuilderImage || c.User != "1000:1000" || !slices.Equal(c.Entrypoint, []string{"/bin/sh", "-ec", nativeDeadlineCommand, "mydc-build", strconv.FormatUint(spec.CreatedAt+spec.Policy.Seconds, 10), "/usr/bin/buildctl-daemonless.sh"}) || c.Tty || c.OpenStdin || h.Privileged || h.AutoRemove || h.NetworkMode == "host" || h.PidMode != "" || h.RestartPolicy.Name != "no" || h.LogConfig.Type != "none" || !h.ReadonlyRootfs || h.Memory != spec.Policy.MemoryBytes || h.MemorySwap != spec.Policy.MemoryBytes || h.NanoCPUs != int64(spec.Policy.CPUMillis)*1_000_000 {
		t.Fatal("broadened rootless SDK execution")
	}
	for _, m := range h.Mounts {
		if m.Type != mount.TypeBind || !strings.HasPrefix(m.Source, spec.Scope.Root.Path+"/.mydc-imagebuild/") || m.BindOptions == nil || m.BindOptions.Propagation != mount.PropagationRPrivate || m.VolumeOptions != nil {
			t.Fatal("unowned/path/socket mount", m)
		}
	}
	for _, arg := range c.Cmd {
		if arg == "--allow" || strings.Contains(arg, "password") || strings.Contains(arg, "DOCKER_CONFIG") {
			t.Fatal("credential/entitlement in argv")
		}
	}
	if !slices.Contains(c.Cmd, "id=signing,src=/input/secrets/signing") {
		t.Fatal("secret reference was not a file mount")
	}
	if !slices.Contains(c.Cmd, "build-arg:SHELL_TEXT="+spec.Context.Arguments["SHELL_TEXT"]) || strings.Contains(strings.Join(c.Entrypoint, " "), spec.Context.Arguments["SHELL_TEXT"]) {
		t.Fatal("public ARG was interpolated into the deadline shell")
	}
	changed := plan
	changed.Cache[0] ^= 1
	if _, err := changed.CreateOptions(spec); err == nil {
		t.Fatal("another cache scope accepted")
	}
	other := spec.Own()
	other.ID = "build-two"
	next, err := PlanNative(other, engine.Owner(other.Cluster, other.Scope.Root.Key))
	if err != nil || next.Container.Name == plan.Container.Name || nativeWorkspaceNames(next)[0] == nativeWorkspaceNames(plan)[0] || next.Cache != plan.Cache {
		t.Fatal("job inputs mixed or context cache identity changed", err)
	}
}
