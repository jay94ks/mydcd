// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

func TestContainerDetailProjectsDriftWithoutEnvValuesHostPathsOrHealthOutput(t *testing.T) {
	secret := "private-value-marker-419"
	filter, err := containerops.NewRedactor(io.Discard, []containerops.RedactionValue{{Reference: "tenant/signing/TOKEN", Value: []byte(secret)}})
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Destroy()
	process := Process{ImageID: "sha256:" + strings.Repeat("a", 64), Command: []string{"run"}, Entrypoint: []string{"/program"}, User: "10001:10001", Env: []string{"MODE=production", "IMAGE_ONLY=image-internal", "MY_PASS=image-default"}, StopSignal: "SIGTERM"}
	spec := ContainerSpec{Schema: 1, Image: "docker.io/library/example@sha256:" + strings.Repeat("b", 64), Memory: 32 << 20, NanoCPU: 100000000, Process: &process}
	config, err := process.ContainerConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	config.Env = []string{"MODE=production", "IMAGE_ONLY=image-internal", "MY_PASS=" + secret, "NATIVE_ONLY=foreign-private-value"}
	config.Cmd = []string{"run", secret}
	got := container.InspectResponse{ID: strings.Repeat("c", 64), Name: "/owned-original", Image: process.ImageID, Config: config, HostConfig: &container.HostConfig{ReadonlyRootfs: true, Privileged: true, Resources: container.Resources{Memory: 64 << 20, NanoCPUs: spec.NanoCPU}, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "10m", "awslogs-secret": "logger-private-credential"}}}, State: &container.State{Status: container.StateExited, ExitCode: 137, StartedAt: "2026-11-21T00:00:00Z", FinishedAt: "2026-11-21T00:01:00Z", Health: &container.Health{FailingStreak: 2, Log: []*container.HealthcheckResult{{Start: time.Unix(100, 0), End: time.Unix(101, 0), ExitCode: 1, Output: secret}}}}, NetworkSettings: &container.NetworkSettings{}, Mounts: []container.MountPoint{{Type: mount.TypeBind, Source: "/private/node/inputs/never-public", Destination: "/etc/app/key.pem", RW: false}}}
	files := []InputFile{{Source: "/private/node/inputs/never-public", Target: "/etc/app/key.pem", UID: 10001, GID: 10001, Mode: 0400, Reference: "tenant/signing/TOKEN"}, {Kind: "env", Target: "MY_PASS", Mode: 0400, Reference: "tenant/signing/TOKEN"}}
	decl := containerops.DetailDeclaration{Environment: map[string]string{"MODE": "production"}, NetworkAliases: map[string][]string{"app-net": {"api"}}}
	got.HostConfig.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
	detail, err := containerDetail(spec, engine.Identity{Name: "owned-original"}, got, files, nil, nil, []string{"MODE=production", "IMAGE_ONLY=image-internal", "MY_PASS=" + secret}, decl, filter)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(detail.DNS, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Fatal("SDK DNS addresses were not projected as public IP strings")
	}
	if !slices.Contains(detail.Drift, "memory") || !slices.Contains(detail.Drift, "privileged") || !slices.Contains(detail.Drift, "command") || !slices.Contains(detail.Drift, "environment") {
		t.Fatal("native drift was hidden", detail.Drift)
	}
	for _, env := range detail.Environment {
		switch env.Name {
		case "MODE":
			if env.Value == nil || *env.Value != "production" {
				t.Fatal("literal app env missing")
			}
		case "MY_PASS":
			if env.Value != nil || env.Source != "secret" || env.SecretReference != "tenant/signing/TOKEN" {
				t.Fatal("secret env not represented by reference")
			}
		default:
			if env.Value != nil {
				t.Fatal("native/image env value escaped")
			}
		}
	}
	if len(detail.Mounts) != 1 || detail.Mounts[0].Kind != "secret" || detail.Mounts[0].Mode == nil || *detail.Mounts[0].Mode != 0400 || len(detail.Checks) != 1 || detail.Checks[0].Status != "fail" || detail.Checks[0].ConsecutiveFailures == nil || *detail.Checks[0].ConsecutiveFailures != 2 || detail.ExitCode != 137 {
		t.Fatal("actual mount/state/health metadata missing")
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{secret, "/private/node/inputs/never-public", "logger-private-credential", "image-internal", "foreign-private-value"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private native field crossed allowlist", private)
		}
	}
	if !strings.Contains(string(raw), "«가림: tenant/signing/TOKEN»") {
		t.Fatal("free native command text did not use supplied Secret filter")
	}
	if process.Command[0] != "run" || process.Env[2] != "MY_PASS=image-default" || got.Config.Cmd[1] != secret {
		t.Fatal("read-only projection mutated native/desired input")
	}
}
