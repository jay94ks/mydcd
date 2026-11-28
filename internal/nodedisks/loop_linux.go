// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// AttachLoop attaches file to a free loop device and returns its name
// (loopN). The device keeps a reference to the file, so it stays usable
// after the caller closes it; DetachLoop releases it.
func AttachLoop(file string) (string, error) {
	ctl, err := os.OpenFile("/dev/loop-control", os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", refuse("io", "open /dev/loop-control: "+err.Error())
	}
	defer ctl.Close()
	backing, err := os.OpenFile(file, os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", refuse("io", "open "+file+": "+err.Error())
	}
	defer backing.Close()
	for range 8 {
		n, err := unix.IoctlRetInt(int(ctl.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return "", refuse("io", "no free loop device: "+err.Error())
		}
		name := "loop" + strconv.Itoa(n)
		dev, err := os.OpenFile("/dev/"+name, os.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return "", refuse("io", "open /dev/"+name+": "+err.Error())
		}
		cfg := unix.LoopConfig{Fd: uint32(backing.Fd()), Size: 512}
		err = unix.IoctlLoopConfigure(int(dev.Fd()), &cfg)
		dev.Close()
		if errors.Is(err, unix.EBUSY) {
			continue // taken between GET_FREE and CONFIGURE
		}
		if err != nil {
			return "", refuse("io", "attach "+file+" to "+name+": "+err.Error())
		}
		return name, nil
	}
	return "", refuse("io", "no free loop device")
}

// DetachLoop releases a loop device; one already free is fine.
func DetachLoop(name string) error {
	dev, err := os.OpenFile("/dev/"+name, os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return refuse("io", "open /dev/"+name+": "+err.Error())
	}
	defer dev.Close()
	if err := unix.IoctlSetInt(int(dev.Fd()), unix.LOOP_CLR_FD, 0); err != nil && !errors.Is(err, unix.ENXIO) {
		return refuse("io", "detach "+name+": "+err.Error())
	}
	return nil
}

// LoopFor finds the loop device whose backing file is file.
func LoopFor(sys, file string) string {
	entries, _ := os.ReadDir(filepath.Join(sys, "block"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "loop") && sysText(filepath.Join(sys, "block", e.Name(), "loop", "backing_file")) == file {
			return e.Name()
		}
	}
	return ""
}
