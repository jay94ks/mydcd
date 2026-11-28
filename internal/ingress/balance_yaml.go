// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"bytes"
	"errors"
	"time"

	"gopkg.in/yaml.v3"
)

// The yaml form of Balance (app.yaml route balance, balance.yaml) has one
// duration key, `warmup: 30s`, for the slow start. The Go fields and their
// JSON stay SlowStartMS/SlowStartSeconds; yaml always reads SlowStartMS.

var errBalanceYAML = errors.New("invalid balance")

type plainBalance Balance

type balanceYAML struct {
	plainBalance `yaml:",inline"`
	Warmup       string `yaml:"warmup,omitempty"`
}

func (b *Balance) UnmarshalYAML(n *yaml.Node) error {
	raw, err := yaml.Marshal(n)
	if err != nil {
		return errBalanceYAML
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	var v balanceYAML
	if d.Decode(&v) != nil {
		return errBalanceYAML
	}
	out := Balance(v.plainBalance)
	if v.Warmup != "" {
		w, err := time.ParseDuration(v.Warmup)
		if err != nil || w <= 0 || w > time.Hour || w%time.Millisecond != 0 {
			return errBalanceYAML
		}
		out.SlowStartMS = int(w.Milliseconds())
	}
	*b = out
	return nil
}

func (b Balance) MarshalYAML() (any, error) {
	v := balanceYAML{plainBalance: plainBalance(b)}
	ms := b.SlowStartMS
	if b.SlowStartSeconds > 0 {
		ms = b.SlowStartSeconds * 1000
	}
	if ms > 0 {
		v.Warmup = (time.Duration(ms) * time.Millisecond).String()
	}
	v.SlowStartMS, v.SlowStartSeconds = 0, 0
	return v, nil
}
