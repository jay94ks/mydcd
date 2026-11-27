// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bufio"
	"errors"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"io"
	"os"
	"strconv"
	"strings"
)

type CPUCounter struct{ Total, Idle, Count uint64 }

// CPUUsage is a reusable pure delta calculation. First/reset/empty samples are
// unknown, not zero host usage. There is no timer, sleep or OS read in the core.
func CPUUsage(previous, current CPUCounter) *uint64 {
	if previous.Count == 0 || previous.Count != current.Count || current.Total <= previous.Total || current.Idle < previous.Idle {
		return nil
	}
	total, idle := current.Total-previous.Total, current.Idle-previous.Idle
	if idle > total {
		return nil
	}
	value := uint64(float64(total-idle) / float64(total) * float64(current.Count) * 1e9)
	return &value
}

func ReadHost(previous CPUCounter) (Host, CPUCounter, error) {
	h := Host{Version: buildinfo.Version(), Features: buildinfo.Own.Names()}
	stat, err := os.Open("/proc/stat")
	if err != nil {
		return h, CPUCounter{}, err
	}
	counter, err := parseCPU(io.LimitReader(stat, 1<<20))
	_ = stat.Close()
	if err != nil {
		return h, CPUCounter{}, err
	}
	h.CPUCapacity, h.CPUUsed = counter.Count*1_000_000_000, CPUUsage(previous, counter)
	memory, err := os.Open("/proc/meminfo")
	if err != nil {
		return h, counter, err
	}
	total, available, err := parseMemory(io.LimitReader(memory, 1<<20))
	_ = memory.Close()
	if err != nil {
		return h, counter, err
	}
	used := total - available
	h.MemoryTotal, h.MemoryUsed = &total, &used
	return h, counter, nil
}

func parseCPU(r io.Reader) (CPUCounter, error) {
	var c CPUCounter
	s := bufio.NewScanner(r)
	found := false
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 2 {
			continue
		}
		if f[0] == "cpu" {
			if found || len(f) < 5 {
				return c, ErrReport
			}
			found = true
			// Linux guest counters are already included in user/nice.
			for i := 1; i < len(f) && i <= 8; i++ {
				n, err := strconv.ParseUint(f[i], 10, 64)
				if err != nil || n > ^uint64(0)-c.Total {
					return c, ErrReport
				}
				c.Total += n
				if i == 4 || i == 5 {
					c.Idle += n
				}
			}
		} else if strings.HasPrefix(f[0], "cpu") {
			if _, err := strconv.ParseUint(strings.TrimPrefix(f[0], "cpu"), 10, 32); err == nil {
				c.Count++
			}
		}
	}
	if s.Err() != nil || !found || c.Count == 0 || c.Count > 1<<16 || c.Total < c.Idle {
		return c, errors.Join(ErrReport, s.Err())
	}
	return c, nil
}

func parseMemory(r io.Reader) (uint64, uint64, error) {
	values := map[string]uint64{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) != 3 || f[0] != "MemTotal:" && f[0] != "MemAvailable:" {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || f[2] != "kB" || n > ^uint64(0)/1024 {
			return 0, 0, ErrReport
		}
		if _, exists := values[f[0]]; exists {
			return 0, 0, ErrReport
		}
		values[f[0]] = n * 1024
	}
	total, ok := values["MemTotal:"]
	available, known := values["MemAvailable:"]
	if s.Err() != nil || !ok || !known || total == 0 || available > total {
		return 0, 0, errors.Join(ErrReport, s.Err())
	}
	return total, available, nil
}
