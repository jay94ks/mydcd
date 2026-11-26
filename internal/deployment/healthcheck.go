// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/moby/moby/api/types/container"
)

func (h *Healthcheck) disabled() bool {
	return h != nil && (h.Disable || len(h.Test) == 1 && h.Test[0] == "NONE")
}

// dockerConfig is shared by admission and actual image resolution. Test
// omission is an image inheritance request, never a new MyDC probe command.
func (h *Healthcheck) dockerConfig() (*container.HealthConfig, error) {
	if h == nil {
		return nil, nil
	}
	config := &container.HealthConfig{Test: slices.Clone(h.Test), Retries: h.Retries}
	if h.Disable {
		config.Test = []string{"NONE"}
	}
	for _, field := range []struct {
		raw   string
		value *time.Duration
	}{{h.Interval, &config.Interval}, {h.Timeout, &config.Timeout}, {h.StartPeriod, &config.StartPeriod}, {h.StartInterval, &config.StartInterval}} {
		if field.raw == "" {
			continue
		}
		value, err := time.ParseDuration(field.raw)
		if err != nil {
			return nil, workload.ErrProcess
		}
		*field.value = value
	}
	if err := workload.ValidateHealthcheck(config); err != nil {
		return nil, err
	}
	return config, nil
}
