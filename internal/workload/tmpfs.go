// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"errors"
	"path"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
)

var ErrTmpfs = errors.New("invalid or unbounded task tmpfs mount")

type Tmpfs struct {
	Target         string
	SizeBytes      int64
	Mode, UID, GID uint32
}

func MountTarget(target string) bool {
	if target == "/" || len(target) > 256 || !strings.HasPrefix(target, "/") || path.Clean(target) != target || strings.ContainsAny(target, "\\\x00\r\n") {
		return false
	}
	for _, reserved := range []string{"/proc", "/sys", "/dev"} {
		if target == reserved || strings.HasPrefix(target, reserved+"/") {
			return false
		}
	}
	return true
}
func OverlappingMounts(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func ValidateTmpfs(values []Tmpfs, memory int64, otherTargets []string) error {
	if len(values) == 0 {
		return nil
	}
	if len(values) > 64 || memory <= 0 {
		return ErrTmpfs
	}
	var total int64
	for i, v := range values {
		if !MountTarget(v.Target) || v.SizeBytes <= 0 || v.SizeBytes > memory-total || v.Mode&^uint32(07777) != 0 {
			return ErrTmpfs
		}
		total += v.SizeBytes
		for _, old := range values[:i] {
			if OverlappingMounts(v.Target, old.Target) {
				return ErrTmpfs
			}
		}
		for _, target := range otherTargets {
			if OverlappingMounts(v.Target, target) {
				return ErrTmpfs
			}
		}
	}
	return nil
}

// CheckImageMounts requires exact coverage; an ancestor does not suppress an
// image's independent anonymous sub-volume in the Engine.
func CheckImageMounts(volumes map[string]struct{}, targets []string) error {
	for target := range volumes {
		if !MountTarget(target) {
			return ErrProcess
		}
		found := false
		for _, approved := range targets {
			if target == approved {
				found = true
				break
			}
		}
		if !found {
			return ErrProcess
		}
	}
	return nil
}

// HostConfig.Tmpfs supports UID/GID; the Engine's Mounts.TmpfsOptions
// whitelist does not. Only this typed recipe generates the option string.
func tmpfsMounts(values []Tmpfs) map[string]string {
	if len(values) == 0 {
		return nil
	}
	mounts := make(map[string]string, len(values))
	for _, v := range values {
		mounts[v.Target] = "rw,nosuid,nodev,noexec,size=" + strconv.FormatInt(v.SizeBytes, 10) + ",mode=" + strconv.FormatUint(uint64(v.Mode), 8) + ",uid=" + strconv.FormatUint(uint64(v.UID), 10) + ",gid=" + strconv.FormatUint(uint64(v.GID), 10)
	}
	return mounts
}
func matchTmpfs(got container.InspectResponse, values []Tmpfs) bool {
	if got.HostConfig == nil || len(got.HostConfig.Tmpfs) != len(values) {
		return false
	}
	for target, options := range tmpfsMounts(values) {
		if got.HostConfig.Tmpfs[target] != options {
			return false
		}
	}
	return true
}
