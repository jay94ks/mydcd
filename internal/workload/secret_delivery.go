// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"
)

// SecretFileTarget is a container path, never a host path. Docker-owned
// resolver/hostname mounts and kernel pseudo-files cannot be secret targets.
func SecretFileTarget(target string) bool {
	if !MountTarget(target) {
		return false
	}
	for _, reserved := range []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"} {
		if OverlappingMounts(target, reserved) {
			return false
		}
	}
	return true
}

func SecretEnvironmentName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for i, c := range []byte(name) {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// A file projection cannot cover or hide behind an image-declared volume.
func CheckSecretImageMounts(volumes map[string]struct{}, targets []string) error {
	for volume := range volumes {
		for _, target := range targets {
			if OverlappingMounts(volume, target) {
				return ErrInputMount
			}
		}
	}
	return nil
}

func validInputDelivery(f InputFile) bool {
	if f.Kind == "env" {
		return SecretEnvironmentName(f.Target) && f.UID == 0 && f.GID == 0 && f.Mode == 0400
	}
	return (f.Kind == "" || f.Kind == "file") && SecretFileTarget(f.Target) && (f.Mode == 0400 || f.Mode == 0440)
}

func mountedInputFiles(files []InputFile) []InputFile {
	var result []InputFile
	for _, file := range files {
		if file.Kind != "env" {
			result = append(result, file)
		}
	}
	return result
}

// readInputValue is called only with the original verified projection lease.
// It does not expose paths or native errors, follow symlinks, or block on FIFOs.
func readInputValue(ctx context.Context, file InputFile, limit int) ([]byte, error) {
	if ctx.Err() != nil || !validInputDelivery(file) || limit < 0 {
		return nil, ErrInputMount
	}
	f, err := os.OpenFile(file.Source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInputMount
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(limit) {
		return nil, ErrInputMount
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(data) > limit || ctx.Err() != nil {
		clear(data)
		return nil, ErrInputMount
	}
	return data, nil
}

// inputEnvironment changes only the transient native create/inspect config.
// The Process and public recipe retain literal image/app environment values.
func inputEnvironment(ctx context.Context, base []string, files []InputFile) ([]string, error) {
	result := slices.Clone(base)
	total := 0
	for _, value := range result {
		total += len(value) + 1
	}
	for _, file := range files {
		if file.Kind != "env" {
			continue
		}
		raw, err := readInputValue(ctx, file, 64<<10)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(raw) || slices.Contains(raw, byte(0)) {
			clear(raw)
			return nil, ErrInputMount
		}
		value := file.Target + "=" + string(raw)
		clear(raw)
		index := slices.IndexFunc(result, func(v string) bool { name, _, _ := strings.Cut(v, "="); return name == file.Target })
		if index >= 0 {
			total -= len(result[index]) + 1
			result[index] = value
		} else {
			result = append(result, value)
		}
		total += len(value) + 1
		if total > 1<<20 {
			return nil, ErrInputMount
		}
	}
	return result, nil
}
