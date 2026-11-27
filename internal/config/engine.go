// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"regexp"
	"strconv"
	"time"
)

// Engine is node.yaml engine: the per-server settings of this server's
// Seafield engine (sfed). sfcd writes them into the engine's daemon.json
// (`sfcd engine-config`); the engine reads them when it starts, and log
// settings reach containers created after that. Empty fields keep the
// engine's defaults.
type Engine struct {
	// Build false turns image builds off on this server (features.buildkit).
	Build *bool      `yaml:"build,omitempty" json:",omitempty"`
	Logs  EngineLogs `yaml:"logs,omitempty" json:",omitempty"`
}

// EngineLogs is engine.logs: when the engine tells sfcd new log lines are
// queued, and how much it keeps per container until sfcd takes them.
type EngineLogs struct {
	// NotifyQuiet: wait this long after the last line (10ms–10s, default 500ms).
	NotifyQuiet string `yaml:"notify_quiet,omitempty" json:",omitempty"`
	// NotifyMaxWait: tell at least this often while lines keep coming
	// (at least NotifyQuiet, at most 1m, default 5s).
	NotifyMaxWait string `yaml:"notify_max_wait,omitempty" json:",omitempty"`
	// MaxSize caps one container's queue; the oldest lines go first
	// (256k–4g, k/m/g = KiB/MiB/GiB, default 64m).
	MaxSize string `yaml:"max_size,omitempty" json:",omitempty"`
}

const (
	DefaultEngineNotifyQuiet   = 500 * time.Millisecond
	DefaultEngineNotifyMaxWait = 5 * time.Second
	DefaultEngineLogMaxSize    = 64 << 20
)

// BuildEnabled reports whether this server builds images (the default).
func (e Engine) BuildEnabled() bool { return e.Build == nil || *e.Build }

// NotifyQuietDuration is engine.logs.notify_quiet, or the default.
func (l EngineLogs) NotifyQuietDuration() (time.Duration, error) {
	return engineDuration(l.NotifyQuiet, DefaultEngineNotifyQuiet)
}

// NotifyMaxWaitDuration is engine.logs.notify_max_wait, or the default.
func (l EngineLogs) NotifyMaxWaitDuration() (time.Duration, error) {
	return engineDuration(l.NotifyMaxWait, DefaultEngineNotifyMaxWait)
}

// MaxSizeBytes is engine.logs.max_size in bytes, or the default.
func (l EngineLogs) MaxSizeBytes() (int64, error) {
	if l.MaxSize == "" {
		return DefaultEngineLogMaxSize, nil
	}
	m := sizePattern.FindStringSubmatch(l.MaxSize)
	if m == nil {
		return 0, errors.New("engine.logs.max_size must be a whole number with k, m or g (for example 64m)")
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n > 1<<32 {
		return 0, errors.New("engine.logs.max_size is out of range")
	}
	return n << map[string]uint{"": 0, "k": 10, "m": 20, "g": 30}[m[2]], nil
}

var sizePattern = regexp.MustCompile(`^([0-9]{1,10})([kmg]?)$`)

func engineDuration(s string, fallback time.Duration) (time.Duration, error) {
	if s == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, errors.New("engine.logs durations look like 500ms, 2s or 1m")
	}
	return d, nil
}

// Validate checks engine against the ranges the engine accepts, so a bad
// value fails here rather than when the engine starts.
func (e Engine) Validate() error {
	quiet, err := e.Logs.NotifyQuietDuration()
	if err != nil {
		return err
	}
	wait, err := e.Logs.NotifyMaxWaitDuration()
	if err != nil {
		return err
	}
	size, err := e.Logs.MaxSizeBytes()
	if err != nil {
		return err
	}
	switch {
	case quiet < 10*time.Millisecond || quiet > 10*time.Second:
		return errors.New("engine.logs.notify_quiet must be from 10ms to 10s")
	case wait < quiet || wait > time.Minute:
		return errors.New("engine.logs.notify_max_wait must be at least notify_quiet and at most 1m")
	case size < 256<<10 || size > 4<<30:
		return errors.New("engine.logs.max_size must be from 256k to 4g")
	}
	return nil
}
