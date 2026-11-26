// SPDX-License-Identifier: Apache-2.0

package services

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// A DNS process owns its sockets and workers; these FDs are never handed to
// children or other processes. The DB lock alone is not proof they have ended.
// Boot is separately bound by dnsOwnerDisk. PID namespace plus start ticks
// prevents a reused PID (or a different container's PID) becoming that owner.
type dnsProcessIdentity struct {
	PID                             int
	StartTicks                      uint64
	NamespaceDevice, NamespaceInode uint64
}

func dnsProcessStart(raw []byte) (uint64, error) {
	// comm may contain spaces and parentheses; fields after its last ')' start
	// at field 3. starttime is field 22 in proc_pid_stat(5).
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, ErrLease
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, ErrLease
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, ErrLease
	}
	return start, nil
}

func currentDNSProcess() (dnsProcessIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &stat); err != nil {
		return dnsProcessIdentity{}, err
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return dnsProcessIdentity{}, err
	}
	start, err := dnsProcessStart(raw)
	return dnsProcessIdentity{os.Getpid(), start, uint64(stat.Dev), stat.Ino}, err
}

func dnsOriginalProcessEnded(old *dnsProcessIdentity, current dnsProcessIdentity) error {
	if old == nil || old.PID <= 0 || old.StartTicks == 0 || old.NamespaceInode == 0 || old.NamespaceDevice != current.NamespaceDevice || old.NamespaceInode != current.NamespaceInode {
		return fmt.Errorf("DNS unclean recovery: missing or different process namespace: %w", ErrLease)
	}
	fd, err := unix.PidfdOpen(old.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("DNS original process pidfd: %w", err)
	}
	defer unix.Close(fd)
	raw, statErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", old.PID))
	if statErr == nil {
		start, err := dnsProcessStart(raw)
		if err != nil {
			return err
		}
		if start != old.StartTicks {
			return nil // the old process ended before this PID was reused
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if _, err = unix.Poll(poll, 0); err != nil {
		return err
	}
	if poll[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
		return fmt.Errorf("DNS original process has not exited: %w", ErrLease)
	}
	return nil
}
