// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

var (
	ErrStopPolicy = errors.New("invalid container stop policy")
	ErrStopBudget = errors.New("remaining operation deadline is shorter than container stop grace")
)

const (
	DefaultStopGrace = 10
	MaxStopGrace     = 24 * 60 * 60
	stopReplyBudget  = 5 * time.Second
)

// StopPolicy belongs to the original Task. An empty Signal inherits the
// frozen image Process signal; GraceSeconds=0 explicitly requests no grace.
type StopPolicy struct {
	GraceSeconds int
	Signal       string
}

// NormalizeStopSignal supports named or numeric conventional Linux signals.
// Names are canonicalized using the pinned x/sys table, not a second table.
func NormalizeStopSignal(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 32 || value != strings.TrimSpace(value) {
		return "", ErrStopPolicy
	}
	n, err := strconv.Atoi(value)
	if err == nil {
		if n <= 0 || n >= 32 || strconv.Itoa(n) != value {
			return "", ErrStopPolicy
		}
		name := unix.SignalName(syscall.Signal(n))
		if name == "" {
			return "", ErrStopPolicy
		}
		return name, nil
	}
	name := strings.ToUpper(value)
	if !strings.HasPrefix(name, "SIG") {
		name = "SIG" + name
	}
	number := unix.SignalNum(name)
	if number <= 0 || number >= 32 {
		return "", ErrStopPolicy
	}
	return unix.SignalName(number), nil
}

func (p StopPolicy) Validate() error {
	normal, err := NormalizeStopSignal(p.Signal)
	if err != nil || normal != p.Signal || p.GraceSeconds < 0 || p.GraceSeconds > MaxStopGrace {
		return ErrStopPolicy
	}
	return nil
}

func ParseStopPolicy(grace, signal string) (*StopPolicy, error) {
	if grace == "" && signal == "" {
		return nil, nil
	}
	p := StopPolicy{GraceSeconds: DefaultStopGrace}
	var err error
	p.Signal, err = NormalizeStopSignal(signal)
	if err != nil {
		return nil, err
	}
	if grace != "" {
		d, err := time.ParseDuration(grace)
		if err != nil || d < 0 || d > time.Duration(MaxStopGrace)*time.Second {
			return nil, ErrStopPolicy
		}
		p.GraceSeconds = int(d / time.Second)
		if d%time.Second != 0 {
			p.GraceSeconds++
		}
	}
	return &p, p.Validate()
}

// StopPolicyFromSpec projects ONLY public stop metadata. The workload adapter
// still validates the full Task/spec and native ownership before effect. Volume
// activation can reuse this projection without importing workload (a cycle).
func StopPolicyFromSpec(raw string) (StopPolicy, error) {
	var envelope struct {
		Schema  uint8
		Stop    json.RawMessage
		Process *struct{ StopSignal string }
	}
	if json.Unmarshal([]byte(raw), &envelope) != nil || envelope.Schema != 1 {
		return StopPolicy{}, ErrStopPolicy
	}
	p := StopPolicy{GraceSeconds: DefaultStopGrace}
	if len(envelope.Stop) != 0 {
		var err error
		p, err = schema.Decode[StopPolicy](envelope.Stop)
		if err != nil || string(envelope.Stop) == "null" || p.Validate() != nil {
			return StopPolicy{}, ErrStopPolicy
		}
	}
	imageSignal := ""
	if envelope.Process != nil {
		var err error
		imageSignal, err = NormalizeStopSignal(envelope.Process.StopSignal)
		if err != nil {
			return StopPolicy{}, err
		}
	}
	if p.Signal != "" && imageSignal != p.Signal {
		return StopPolicy{}, ErrStopPolicy
	}
	if p.Signal == "" {
		p.Signal = imageSignal
	}
	if p.Signal == "" {
		p.Signal = "SIGTERM"
	}
	return p, nil
}

func MatchStopPolicy(raw string, cfg *container.Config) (StopPolicy, error) {
	p, err := StopPolicyFromSpec(raw)
	if err != nil || cfg == nil {
		return StopPolicy{}, errors.Join(ErrStopPolicy, err)
	}
	signal, err := NormalizeStopSignal(cfg.StopSignal)
	if signal == "" && err == nil {
		signal = "SIGTERM"
	}
	if err != nil || signal != p.Signal || cfg.StopTimeout != nil && *cfg.StopTimeout != p.GraceSeconds || cfg.StopTimeout == nil && p.GraceSeconds != DefaultStopGrace {
		return StopPolicy{}, ErrStopPolicy
	}
	return p, nil
}

// StopContainer performs one request against the same configured Engine. The
// caller owns original dispatch/recovery and must inspect exit/removal before
// returning any pin; a timeout is an unknown effect, never successful closure.
func (c *Client) StopContainer(ctx context.Context, native string, p StopPolicy) error {
	if c == nil || c.API == nil || ctx == nil || p.Validate() != nil || p.Signal == "" || native == "" {
		return ErrStopPolicy
	}
	if err := CheckStopBudget(ctx, p); err != nil {
		return err
	}
	grace := time.Duration(p.GraceSeconds) * time.Second
	request, cancel := context.WithTimeout(ctx, grace+stopReplyBudget)
	defer cancel()
	api := c.stopAPI
	if api == nil {
		api = c.API // SDK-only fixtures; production Open always installs stopAPI.
	}
	_, err := api.ContainerStop(request, native, client.ContainerStopOptions{Timeout: &p.GraceSeconds, Signal: p.Signal})
	return err
}

func CheckStopBudget(ctx context.Context, p StopPolicy) error {
	if ctx == nil || p.Validate() != nil {
		return ErrStopPolicy
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	grace := time.Duration(p.GraceSeconds) * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < grace {
		return fmt.Errorf("%w (grace=%s)", ErrStopBudget, grace)
	}
	return nil
}
