// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrKeep is a keep value that is neither a duration nor "forever".
var ErrKeep = errors.New(`logs keep must be a duration ("168h", "7d") or "forever"`)

var keepDays = regexp.MustCompile(`^([0-9]+)d$`)

// ParseKeep reads a logs keep value (node.yaml logs.keep, app.yaml
// x-sfc.logs.keep): a duration with d allowed ("7d", "168h") or "forever"
// (0). ok is false for an empty value.
func ParseKeep(v string) (d time.Duration, ok bool, err error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return 0, false, nil
	case v == "forever":
		return 0, true, nil
	case keepDays.MatchString(v):
		n, err := strconv.ParseInt(keepDays.FindStringSubmatch(v)[1], 10, 64)
		if err != nil || n <= 0 || n > 100000 {
			return 0, false, ErrKeep
		}
		return time.Duration(n) * 24 * time.Hour, true, nil
	}
	d, err = time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false, ErrKeep
	}
	return d, true, nil
}
