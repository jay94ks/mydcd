// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"strings"

	"github.com/moby/moby/api/types/container"
)

// Summarize uses only the supplied Engine sample. Missing/baseline/reset data
// stay unavailable; counter deltas never wrap into a plausible usage value.
func Summarize(s container.StatsResponse) Stats {
	out := Stats{SampleAt: s.Read, CPUStatus: "unavailable"}
	cpu, previous := s.CPUStats, s.PreCPUStats
	cores := cpu.OnlineCPUs
	if cores == 0 {
		cores = uint32(len(cpu.CPUUsage.PercpuUsage))
	}
	if s.PreRead.IsZero() || !s.Read.After(s.PreRead) {
		out.CPUStatus = "warming-up"
	} else if cpu.CPUUsage.TotalUsage < previous.CPUUsage.TotalUsage || cpu.SystemUsage < previous.SystemUsage {
		out.CPUStatus = "counter-reset"
	} else if cores > 0 && cpu.SystemUsage > previous.SystemUsage {
		v := float64(cpu.CPUUsage.TotalUsage-previous.CPUUsage.TotalUsage) / float64(cpu.SystemUsage-previous.SystemUsage) * float64(cores) * 100
		out.CPUPercent, out.CPUStatus = &v, "ok"
	}
	memory := s.MemoryStats
	if memory.Limit != 0 || memory.Usage != 0 || memory.Stats != nil {
		used, limit, working := memory.Usage, memory.Limit, memory.Usage
		cache, ok := memory.Stats["total_inactive_file"]
		if !ok {
			cache, ok = memory.Stats["inactive_file"]
		}
		out.MemoryBytes, out.MemoryLimitBytes = &used, &limit
		if ok && cache <= working {
			working -= cache
			out.MemoryWorkingSetBytes = &working
		}
	}
	if s.Networks != nil {
		var rx, tx uint64
		for _, n := range s.Networks {
			if ^uint64(0)-rx < n.RxBytes || ^uint64(0)-tx < n.TxBytes {
				return out
			}
			rx += n.RxBytes
			tx += n.TxBytes
		}
		out.NetworkRXBytes, out.NetworkTXBytes = &rx, &tx
	}
	if s.BlkioStats.IoServiceBytesRecursive != nil {
		var read, write uint64
		valid := true
		for _, entry := range s.BlkioStats.IoServiceBytesRecursive {
			switch strings.ToLower(entry.Op) {
			case "read":
				if ^uint64(0)-read < entry.Value {
					valid = false
				} else {
					read += entry.Value
				}
			case "write":
				if ^uint64(0)-write < entry.Value {
					valid = false
				} else {
					write += entry.Value
				}
			}
		}
		if valid {
			out.BlockReadBytes, out.BlockWriteBytes = &read, &write
		}
	}
	if s.OSType == "linux" && !s.Read.IsZero() {
		pids := s.PidsStats.Current
		out.PIDs = &pids
	}
	return out
}
