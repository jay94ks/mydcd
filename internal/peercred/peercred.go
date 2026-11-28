// SPDX-License-Identifier: Apache-2.0

// Package peercred proves which process is on the other end of a local Unix
// socket. It reads only kernel facts: SO_PEERCRED/SO_PEERPIDFD for the peer
// that connected, SCM_CREDENTIALS/SCM_PIDFD for the sender of the next bytes,
// and a pidfd to keep the answer tied to one live process. It knows nothing
// about Docker, the engine or the vault; callers decide what a match means.
package peercred

import "errors"

// ErrIdentity means the kernel did not positively identify one live peer
// process, or that process is not the one the caller asked about.
var ErrIdentity = errors.New("peer process identity not proven")

// Process is one peer process the kernel named. FD is a pidfd for that exact
// process; the caller owns it and must Close it.
type Process struct {
	PID int
	UID uint32
	GID uint32
	FD  int
}
