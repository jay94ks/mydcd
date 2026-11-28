// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/jay94ks/seafield/internal/bootstrap"
	"golang.org/x/sys/unix"
)

func unmountInputMemory(stateDir string) {
	_ = unix.Unmount(filepath.Join(stateDir, filepath.FromSlash(bootstrap.InputMemoryDir)), unix.MNT_DETACH)
}
