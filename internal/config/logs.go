// SPDX-License-Identifier: Apache-2.0

package config

import (
	"github.com/jay94ks/seafield/internal/logstore"

	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Logs is node.yaml logs: how much this server's sfcd log store
// (StateDir/logs) keeps. Logs of containers that still exist are bounded
// by their own per-container cap; these settings remove logs of containers
// that are gone (devel/design/yaml-formats.md 3.2).
type Logs struct {
	// Limit caps the whole store: "5%" of the store's disk, or a size such
	// as "10GiB" (KiB/MiB/GiB/TiB). Over it, the logs of the longest-gone
	// containers go first. Default 5%, held to 1GiB–20GiB.
	Limit string `yaml:"limit,omitempty" json:",omitempty"`
	// Keep is how long a gone container's log is kept: a duration ("168h",
	// "7d") or "forever". Default 7d.
	Keep string `yaml:"keep,omitempty" json:",omitempty"`
}

const (
	DefaultLogsLimitPercent = 5
	MinLogsLimit            = 1 << 30
	MaxLogsLimit            = 20 << 30
	DefaultLogsKeep         = 7 * 24 * time.Hour
)

var (
	logsPercent = regexp.MustCompile(`^([0-9]{1,2}(?:\.[0-9]+)?)%$`)
	logsSize    = regexp.MustCompile(`^([0-9]+)(KiB|MiB|GiB|TiB)$`)
)

// LimitBytes is logs.limit in bytes for a store on a disk of diskBytes.
// A percentage (also the default) is held to 1GiB–20GiB; a size is used
// as given.
func (l Logs) LimitBytes(diskBytes int64) (int64, error) {
	pct := float64(DefaultLogsLimitPercent)
	switch v := strings.TrimSpace(l.Limit); {
	case v == "":
	case logsPercent.MatchString(v):
		pct, _ = strconv.ParseFloat(logsPercent.FindStringSubmatch(v)[1], 64)
		if pct <= 0 {
			return 0, errors.New("logs.limit must be more than 0%")
		}
	case logsSize.MatchString(v):
		m := logsSize.FindStringSubmatch(v)
		n, err := strconv.ParseInt(m[1], 10, 64)
		shift := map[string]uint{"KiB": 10, "MiB": 20, "GiB": 30, "TiB": 40}[m[2]]
		if err != nil || n <= 0 || n > (1<<62)>>shift {
			return 0, errors.New("logs.limit is out of range")
		}
		return n << shift, nil
	default:
		return 0, errors.New(`logs.limit must be a percentage ("5%") or a size ("10GiB")`)
	}
	return min(max(int64(float64(diskBytes)*pct/100), MinLogsLimit), MaxLogsLimit), nil
}

// KeepDuration is logs.keep; 0 means forever.
func (l Logs) KeepDuration() (time.Duration, error) {
	d, ok, err := logstore.ParseKeep(l.Keep)
	if err != nil {
		return 0, errors.New(`logs.keep must be a duration ("168h", "7d") or "forever"`)
	}
	if !ok {
		return DefaultLogsKeep, nil
	}
	return d, nil
}

// Validate checks the logs section.
func (l Logs) Validate() error {
	if _, err := l.LimitBytes(1 << 40); err != nil {
		return err
	}
	_, err := l.KeepDuration()
	return err
}
