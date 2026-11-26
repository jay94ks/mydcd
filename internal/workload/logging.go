// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"errors"
	"maps"
	"strconv"
	"strings"

	"github.com/docker/go-units"
	"github.com/moby/moby/api/types/container"
)

var ErrLogPolicy = errors.New("invalid or unsupported container logging policy")

// LogPolicy controls only an app-owned container's Engine logging configuration.
// Absence preserves daemon inheritance and the bytes of old accepted tasks.
type LogPolicy struct {
	Driver  string            `yaml:"driver"`
	Options map[string]string `yaml:"options,omitempty" json:",omitempty"`
}

func (p LogPolicy) Validate() error {
	if p.Driver != "local" && p.Driver != "json-file" {
		return ErrLogPolicy
	}
	for key, value := range p.Options {
		if len(value) == 0 || len(value) > 64 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return ErrLogPolicy
		}
		switch key {
		case "max-size":
			size, err := units.FromHumanSize(value)
			if err != nil || size <= 0 {
				return ErrLogPolicy
			}
		case "max-file":
			count, err := strconv.ParseInt(value, 10, 64)
			if err != nil || count < 1 {
				return ErrLogPolicy
			}
		case "compress":
			if value != "true" && value != "false" {
				return ErrLogPolicy
			}
		default:
			return ErrLogPolicy
		}
	}
	return nil
}
func (p *LogPolicy) Clone() *LogPolicy {
	if p == nil {
		return nil
	}
	return &LogPolicy{Driver: p.Driver, Options: maps.Clone(p.Options)}
}
func (p LogPolicy) Native() container.LogConfig {
	return container.LogConfig{Type: p.Driver, Config: maps.Clone(p.Options)}
}

// Matches pins explicit options; Engine may fill undeclared daemon defaults.
// A changed driver or declared rotation value cannot be claimed as this task.
func (p *LogPolicy) Matches(actual container.LogConfig) bool {
	if p == nil {
		return true
	}
	if p.Validate() != nil || actual.Type != p.Driver {
		return false
	}
	for key, value := range p.Options {
		if actual.Config[key] != value {
			return false
		}
	}
	return true
}
