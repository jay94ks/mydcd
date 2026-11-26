// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"math"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/workload"
)

func parseTmpfs(raw string) (workload.Tmpfs, error) {
	target, options, has := strings.Cut(raw, ":")
	v := workload.Tmpfs{Target: target, Mode: 01777}
	if !has || !workload.MountTarget(target) {
		return v, workload.ErrTmpfs
	}
	seen := map[string]bool{}
	for _, option := range strings.Split(options, ",") {
		k, value, ok := strings.Cut(option, "=")
		if !ok || seen[k] {
			return v, workload.ErrTmpfs
		}
		seen[k] = true
		switch k {
		case "size":
			n, err := byteSize(value)
			if err != nil || n == 0 || n > math.MaxInt64 {
				return v, workload.ErrTmpfs
			}
			v.SizeBytes = int64(n)
		case "mode":
			n, err := strconv.ParseUint(value, 8, 12)
			if err != nil {
				return v, workload.ErrTmpfs
			}
			v.Mode = uint32(n)
		case "uid", "gid":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return v, workload.ErrTmpfs
			}
			if k == "uid" {
				v.UID = uint32(n)
			} else {
				v.GID = uint32(n)
			}
		default:
			return v, workload.ErrTmpfs
		}
	}
	if !seen["size"] {
		return v, workload.ErrTmpfs
	}
	return v, nil
}

// TmpfsMounts is the same conversion used by early file validation and the
// actual native consumer. memory is the resolved task budget, not a host value.
func (s ComposeService) TmpfsMounts(memory int64) ([]workload.Tmpfs, error) {
	var result []workload.Tmpfs
	for _, raw := range s.Tmpfs {
		v, err := parseTmpfs(raw)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	var targets []string
	for _, m := range s.Volumes {
		targets = append(targets, m.Target)
	}
	for _, m := range s.Secrets {
		targets = append(targets, m.Target)
	}
	if workload.ValidateTmpfs(result, memory, targets) != nil {
		return nil, workload.ErrTmpfs
	}
	return result, nil
}
