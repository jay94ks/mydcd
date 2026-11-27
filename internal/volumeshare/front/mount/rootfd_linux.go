// SPDX-License-Identifier: Apache-2.0

package mount

import "golang.org/x/sys/unix"

// RootFD opens the root of a mount this process serves, for the engine's
// volume mount answer: the engine clones it with open_tree and binds the
// clone into the container, so the path is never resolved again. It uses a
// plain open(2): os.Open would register the descriptor with the netpoller,
// whose FUSE_POLL deadlocks against the serving goroutines.
func RootFD(dir string) (fd int, dev, ino uint64, err error) {
	fd, err = unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, 0, 0, err
	}
	return fd, uint64(st.Dev), st.Ino, nil
}
