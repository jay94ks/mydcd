// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"strings"
	"testing"
)

func TestHostCPUDeltaAndMemoryDoNotInventMissingUsage(t *testing.T) {
	counter, err := parseCPU(strings.NewReader("cpu  10 0 20 70 0 0 0 0 8 0\ncpu0 1 0 0 0\ncpu1 1 0 0 0\n"))
	if err != nil || counter.Total != 100 || counter.Idle != 70 || counter.Count != 2 {
		t.Fatal(counter, err)
	}
	if CPUUsage(CPUCounter{}, counter) != nil || CPUUsage(counter, counter) != nil || CPUUsage(counter, CPUCounter{Total: 101, Idle: 72, Count: 2}) != nil {
		t.Fatal("missing/reset/impossible CPU delta became known usage")
	}
	previous := counter
	counter.Total += 100
	counter.Idle += 50
	used := CPUUsage(previous, counter)
	if used == nil || *used != 1e9 {
		t.Fatal("two-CPU half utilization", used)
	}
	if steal := CPUSteal(previous, counter); steal == nil || *steal != 0 {
		t.Fatal("no steal delta", steal)
	}
	total, available, err := parseMemory(strings.NewReader("MemTotal: 1024 kB\nMemAvailable: 256 kB\n"))
	if err != nil || total != 1048576 || available != 262144 {
		t.Fatal(total, available, err)
	}
	for _, raw := range []string{"MemTotal: 1024 kB\n", "MemTotal: 1 kB\nMemAvailable: 2 kB\n", "MemTotal: 1 kB\nMemTotal: 2 kB\nMemAvailable: 0 kB\n"} {
		if _, _, err := parseMemory(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid memory counters accepted", raw)
		}
	}
}

func TestSelectedMountUsesPathBoundaryAndFilesystemIdentityDeduplicates(t *testing.T) {
	mounts := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n3 1 8:3 / /data\\040files rw - xfs /dev/sdc1 rw\n"
	for _, test := range []struct{ path, mount, device string }{{"/database", "/", "/dev/sda1"}, {"/data/a", "/data", "/dev/sdb1"}, {"/data files/a", "/data files", "/dev/sdc1"}} {
		mount, device, _, err := selectedMount(strings.NewReader(mounts), test.path)
		if err != nil || mount != test.mount || device != test.device {
			t.Fatal(test, mount, device, err)
		}
	}
	if FilesystemID("node-a", "same-device-and-fsid") != FilesystemID("node-a", "same-device-and-fsid") || FilesystemID("node-a", "same-device-and-fsid") == FilesystemID("node-b", "same-device-and-fsid") {
		t.Fatal("filesystem identity lost node boundary")
	}
}

// A shared VPS: the hypervisor ran other guests for part of the window.
// Stolen time is neither this server's usage nor idle; it is reported apart.
func TestHostCPUStealIsNotUsage(t *testing.T) {
	previous, err := parseCPU(strings.NewReader("cpu  10 0 10 70 0 0 0 10 0 0\ncpu0 1 0 0 0\n"))
	if err != nil || previous.Total != 100 || previous.Idle != 70 || previous.Steal != 10 || previous.Count != 1 {
		t.Fatal(previous, err)
	}
	// 100 ticks later: 10 user, 50 idle, 40 steal.
	current, err := parseCPU(strings.NewReader("cpu  20 0 10 120 0 0 0 50 0 0\ncpu0 1 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	used, steal := CPUUsage(previous, current), CPUSteal(previous, current)
	if used == nil || *used != 1e8 || steal == nil || *steal != 4e8 {
		t.Fatal("used/steal", used, steal)
	}
	backwards := current
	backwards.Total, backwards.Steal = current.Total+10, previous.Steal-1
	if CPUUsage(current, backwards) != nil || CPUSteal(current, backwards) != nil {
		t.Fatal("steal counter going backwards became known usage")
	}
}
