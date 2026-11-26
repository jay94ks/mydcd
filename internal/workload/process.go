// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"errors"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/moby/moby/api/types/container"
)

var ErrProcess = errors.New("invalid or unsupported image execution configuration")

// Process is the frozen effective configuration of an immutable image. It is
// shared metadata, never a place for fetched Secret values or host paths.
type Process struct {
	ImageID                      string
	Command, Entrypoint, Env     []string
	User, WorkingDir, StopSignal string
	Healthcheck                  *container.HealthConfig `json:",omitempty"`
}

type ProcessOverrides struct {
	WorkingDir          string
	Command, Entrypoint *[]string
	Environment         map[string]string
	User                string
	StopSignal          string
	Healthcheck         *container.HealthConfig
	MountTargets        []string
}

func cloneHealth(h *container.HealthConfig) *container.HealthConfig {
	if h == nil {
		return nil
	}
	n := *h
	n.Test = slices.Clone(h.Test)
	return &n
}

func numericUser(user string) bool {
	parts := strings.Split(user, ":")
	if len(parts) != 2 {
		return false
	}
	for _, v := range parts {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			return false
		}
	}
	return true
}

func validArguments(args []string) bool {
	if len(args) > 128 {
		return false
	}
	for _, a := range args {
		if len(a) > 4096 || strings.ContainsAny(a, "\x00\r\n") {
			return false
		}
	}
	return true
}

func environmentKey(k string) bool {
	if len(k) == 0 || len(k) > 256 {
		return false
	}
	for i, c := range []byte(k) {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func imageEnvironment(env []string) (map[string]string, error) {
	if len(env) > 128 {
		return nil, ErrProcess
	}
	values := map[string]string{}
	for _, raw := range env {
		k, v, ok := strings.Cut(raw, "=")
		if !ok || !environmentKey(k) || len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return nil, ErrProcess
		}
		if _, duplicate := values[k]; duplicate {
			return nil, ErrProcess
		}
		values[k] = v
	}
	return values, nil
}

// ValidateHealthcheck validates Docker's health configuration, including an
// override with no Test yet. ResolveProcess joins that override to the actual
// image; Process.Validate requires a concrete test (or explicit NONE).
func ValidateHealthcheck(h *container.HealthConfig) error {
	if h == nil {
		return nil
	}
	if len(h.Test) > 128 || h.Retries < 0 || h.Retries > 100 {
		return ErrProcess
	}
	for _, arg := range h.Test {
		// An explicit shell healthcheck may contain a multiline script. No
		// host shell or automatic shell conversion is introduced here.
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return ErrProcess
		}
	}
	if len(h.Test) != 0 && !(len(h.Test) == 1 && h.Test[0] == "NONE" || len(h.Test) > 1 && (h.Test[0] == "CMD" || h.Test[0] == "CMD-SHELL")) {
		return ErrProcess
	}
	for _, d := range []time.Duration{h.Interval, h.Timeout, h.StartPeriod, h.StartInterval} {
		if d < 0 || d > time.Hour || d > 0 && d < container.MinimumDuration {
			return ErrProcess
		}
	}
	return nil
}

func (p Process) Validate() error {
	if _, err := engine.NormalizeStopSignal(p.StopSignal); err != nil {
		return ErrProcess
	}
	if len(p.ImageID) != 71 || !strings.HasPrefix(p.ImageID, "sha256:") || !numericUser(p.User) || !validArguments(p.Command) || !validArguments(p.Entrypoint) || len(p.Command)+len(p.Entrypoint) == 0 || len(p.Entrypoint) > 0 && p.Entrypoint[0] == "" || len(p.Entrypoint) == 0 && p.Command[0] == "" || len(p.StopSignal) > 64 || strings.ContainsAny(p.StopSignal, "\x00\r\n") || ValidateHealthcheck(p.Healthcheck) != nil || p.Healthcheck != nil && len(p.Healthcheck.Test) == 0 {
		return ErrProcess
	}
	for _, c := range p.ImageID[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrProcess
		}
	}
	if p.WorkingDir != "" && (!strings.HasPrefix(p.WorkingDir, "/") || path.Clean(p.WorkingDir) != p.WorkingDir || strings.ContainsAny(p.WorkingDir, "\x00\r\n")) {
		return ErrProcess
	}
	_, err := imageEnvironment(p.Env)
	return err
}

// ResolveProcess consumes actual image metadata. A mount-capable consumer must
// be connected before an image's VOLUME can be admitted; never create anonymous
// storage as a side effect of merely inspecting an image.
func ResolveProcess(id string, image *container.Config, overrides ProcessOverrides) (Process, error) {
	if image == nil || CheckImageMounts(image.Volumes, overrides.MountTargets) != nil || image.ArgsEscaped {
		return Process{}, ErrProcess
	}
	p := Process{ImageID: id, Command: slices.Clone(image.Cmd), Entrypoint: slices.Clone(image.Entrypoint), User: image.User, WorkingDir: image.WorkingDir, StopSignal: image.StopSignal, Healthcheck: cloneHealth(image.Healthcheck)}
	if overrides.Entrypoint != nil {
		p.Entrypoint = slices.Clone(*overrides.Entrypoint)
		p.Command = nil
	}
	if overrides.Command != nil {
		p.Command = slices.Clone(*overrides.Command)
	}
	if overrides.WorkingDir != "" {
		p.WorkingDir = overrides.WorkingDir
	}
	if overrides.User != "" {
		p.User = overrides.User
	}
	if overrides.StopSignal != "" {
		var err error
		p.StopSignal, err = engine.NormalizeStopSignal(overrides.StopSignal)
		if err != nil {
			return Process{}, ErrProcess
		}
	}
	if overrides.Healthcheck != nil {
		h := cloneHealth(overrides.Healthcheck)
		if old := p.Healthcheck; old != nil {
			if len(h.Test) == 0 {
				h.Test = slices.Clone(old.Test)
			}
			if h.Interval == 0 {
				h.Interval = old.Interval
			}
			if h.Timeout == 0 {
				h.Timeout = old.Timeout
			}
			if h.StartPeriod == 0 {
				h.StartPeriod = old.StartPeriod
			}
			if h.StartInterval == 0 {
				h.StartInterval = old.StartInterval
			}
			if h.Retries == 0 {
				h.Retries = old.Retries
			}
		}
		p.Healthcheck = h
	}
	values, err := imageEnvironment(image.Env)
	if err != nil {
		return Process{}, err
	}
	for k, v := range overrides.Environment {
		if !environmentKey(k) || len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return Process{}, ErrProcess
		}
		values[k] = v
	}
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		p.Env = append(p.Env, k+"="+values[k])
	}
	if err = p.Validate(); err != nil {
		return Process{}, err
	}
	return p, nil
}

// ContainerConfig disables Engine's implicit entrypoint inheritance. The
// effective command, env and health are already frozen, not recomputed on retry.
func (p Process) ContainerConfig(labels map[string]string) (*container.Config, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	entry := slices.Clone(p.Entrypoint)
	if len(entry) == 0 {
		entry = []string{""}
	}
	return &container.Config{Image: p.ImageID, Cmd: slices.Clone(p.Command), Entrypoint: entry, Env: slices.Clone(p.Env), User: p.User, WorkingDir: p.WorkingDir, StopSignal: p.StopSignal, Healthcheck: cloneHealth(p.Healthcheck), Labels: maps.Clone(labels)}, nil
}
