// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

func TestImageProcessOmittedEmptyAndExplicitArguments(t *testing.T) {
	image := &container.Config{User: "10001:10001", Cmd: []string{"image-arg"}, Entrypoint: []string{"/image-entry"}}
	id := "sha256:" + strings.Repeat("a", 64)
	empty := []string{}
	cmd := []string{"override-arg"}
	entry := []string{"/new-entry"}
	cases := []struct {
		command, entry         *[]string
		wantCommand, wantEntry []string
		reject                 bool
	}{
		{nil, nil, image.Cmd, image.Entrypoint, false},
		{&empty, nil, empty, image.Entrypoint, false},
		{nil, &empty, nil, nil, true},
		{&cmd, &empty, cmd, empty, false},
		{nil, &entry, nil, entry, false},
		{&cmd, &entry, cmd, entry, false},
		{&empty, &empty, nil, nil, true},
	}
	for i, c := range cases {
		p, err := ResolveProcess(id, image, ProcessOverrides{Command: c.command, Entrypoint: c.entry})
		if c.reject {
			if err == nil {
				t.Fatal("empty execution accepted", i)
			}
			continue
		}
		if err != nil || !slicesEqual(p.Command, c.wantCommand) || !slicesEqual(p.Entrypoint, c.wantEntry) {
			t.Fatal("argv semantics", i, p, err)
		}
		config, err := p.ContainerConfig(map[string]string{"owner": "original"})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Entrypoint) == 0 && !reflect.DeepEqual(config.Entrypoint, []string{""}) {
			t.Fatal("entrypoint clear did not suppress image inheritance")
		}
	}
}

func slicesEqual(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }

func TestImageProcessEnvHealthOwnershipAndNonrootPolicy(t *testing.T) {
	image := &container.Config{User: "10001:10002", Cmd: []string{"/backend"}, Env: []string{"Z=old", "A=original"}, Healthcheck: &container.HealthConfig{Test: []string{"CMD", "/probe"}, Interval: time.Second, Timeout: time.Second, Retries: 2}}
	overrides := ProcessOverrides{Environment: map[string]string{"Z": "", "NEW": "new"}, Healthcheck: &container.HealthConfig{Test: []string{"CMD", "/new-probe"}}}
	p, err := ResolveProcess("sha256:"+strings.Repeat("b", 64), image, overrides)
	if err != nil || !reflect.DeepEqual(p.Env, []string{"A=original", "NEW=new", "Z="}) || p.Healthcheck.Interval != time.Second || p.Healthcheck.Retries != 2 {
		t.Fatal("effective defaults/precedence", p, err)
	}
	image.Cmd[0] = "mutated"
	image.Healthcheck.Test[1] = "mutated"
	overrides.Healthcheck.Test[1] = "mutated"
	overrides.Environment["NEW"] = "mutated"
	if p.Command[0] != "/backend" || p.Healthcheck.Test[1] != "/new-probe" || p.Env[1] != "NEW=new" {
		t.Fatal("caller alias changed frozen process")
	}
	labels := map[string]string{"owner": "original"}
	cfg, err := p.ContainerConfig(labels)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Cmd[0] = "mutated"
	cfg.Healthcheck.Test[1] = "mutated"
	labels["owner"] = "mutated"
	if p.Command[0] != "/backend" || p.Healthcheck.Test[1] != "/new-probe" || cfg.Labels["owner"] != "original" {
		t.Fatal("native options aliased frozen metadata")
	}
	for _, user := range []string{"", "root", "0:10001", "10001:0", "10001", "alice:staff"} {
		bad := p
		bad.User = user
		if bad.Validate() == nil {
			t.Fatal("nonroot numeric policy bypass", user)
		}
	}
}

func TestImageProcessRejectsAnonymousStorageAmbiguousEnvAndInvalidHealth(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	good := container.Config{User: "10001:10001", Cmd: []string{"/backend"}}
	cases := []container.Config{good, good, good, good, good, good}
	cases[0].Volumes = map[string]struct{}{"/data": {}}
	cases[1].Env = []string{"KEY=a", "KEY=b"}
	cases[2].Env = []string{"NO_EQUALS"}
	cases[3].Healthcheck = &container.HealthConfig{Test: []string{"UNSUPPORTED", "do something"}}
	cases[4].Healthcheck = &container.HealthConfig{Test: []string{"CMD", "/probe"}, Timeout: -time.Second}
	cases[5].ArgsEscaped = true
	for i, image := range cases {
		if _, err := ResolveProcess(id, &image, ProcessOverrides{}); err == nil {
			t.Fatal("unsafe image accepted", i)
		}
	}
	for _, bad := range []string{"", "latest", "sha256:" + strings.Repeat("A", 64)} {
		if _, err := ResolveProcess(bad, &good, ProcessOverrides{}); err == nil {
			t.Fatal("mutable/invalid image ID accepted")
		}
	}
}

// Docker executes both modes; these cases check frozen image inheritance and
// SDK options rather than implementing another healthcheck command runner.
func TestImageHealthcheckShellInheritanceDisableAndDockerOptions(t *testing.T) {
	image := &container.Config{User: "10001:10001", Cmd: []string{"/backend"}, Healthcheck: &container.HealthConfig{Test: []string{"CMD-SHELL", "test -f /ready\nexit 0"}, Interval: 5 * time.Second, Timeout: 2 * time.Second, StartPeriod: 20 * time.Second, StartInterval: time.Second, Retries: 4}}
	id := "sha256:" + strings.Repeat("d", 64)
	for _, tc := range []struct {
		name         string
		override     *container.HealthConfig
		wantTest     []string
		wantInterval time.Duration
		wantRetries  int
	}{
		{"image-default", nil, image.Healthcheck.Test, time.Second, 4},
		{"test-omitted", &container.HealthConfig{Retries: 7}, image.Healthcheck.Test, time.Second, 7},
		{"exec-override", &container.HealthConfig{Test: []string{"CMD", "/probe"}, StartInterval: 3 * time.Second}, []string{"CMD", "/probe"}, 3 * time.Second, 4},
		{"disabled", &container.HealthConfig{Test: []string{"NONE"}}, []string{"NONE"}, time.Second, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ResolveProcess(id, image, ProcessOverrides{Healthcheck: tc.override})
			if err != nil || p.Healthcheck == nil {
				t.Fatal(p, err)
			}
			cfg, err := p.ContainerConfig(nil)
			if err != nil || !reflect.DeepEqual(cfg.Healthcheck.Test, tc.wantTest) || cfg.Healthcheck.StartInterval != tc.wantInterval || cfg.Healthcheck.Retries != tc.wantRetries || cfg.Healthcheck.Timeout != 2*time.Second || cfg.Healthcheck.StartPeriod != 20*time.Second {
				t.Fatal("Docker health configuration lost", cfg, err)
			}
			cfg.Healthcheck.Test[0] = "changed"
			if image.Healthcheck.Test[0] != "CMD-SHELL" || p.Healthcheck.Test[0] == "changed" {
				t.Fatal("native options modified frozen/image command")
			}
		})
	}
	withoutHealth := *image
	withoutHealth.Healthcheck = nil
	if _, err := ResolveProcess(id, &withoutHealth, ProcessOverrides{Healthcheck: &container.HealthConfig{Timeout: time.Second}}); err == nil {
		t.Fatal("test omission fabricated an image healthcheck")
	}
	for _, h := range []*container.HealthConfig{
		{Test: []string{"NONE", "extra"}}, {Test: []string{"CMD"}}, {Test: []string{"CMD-SHELL"}},
		{Test: []string{"CMD", "bad\x00command"}}, {Retries: -1}, {Timeout: time.Nanosecond}, {StartInterval: -time.Second},
	} {
		if ValidateHealthcheck(h) == nil {
			t.Fatal("invalid Docker health override accepted", h)
		}
	}
}

// A root or named-user image says what to set, and is still an ErrProcess.
func TestImageProcessNamesTheUserProblem(t *testing.T) {
	id := "sha256:" + strings.Repeat("d", 64)
	for _, user := range []string{"", "nginx", "0:0"} {
		_, err := ResolveProcess(id, &container.Config{User: user, Cmd: []string{"/run"}}, ProcessOverrides{})
		if !errors.Is(err, ErrProcessUser) || !errors.Is(err, ErrProcess) || !strings.Contains(err.Error(), "user:") {
			t.Fatal(user, err)
		}
	}
	if _, err := ResolveProcess(id, &container.Config{Cmd: []string{"/run"}}, ProcessOverrides{User: "10001:10001"}); err != nil {
		t.Fatal("user override refused", err)
	}
}
