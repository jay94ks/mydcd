// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/peercred"
	"github.com/jay94ks/seafield/internal/sfev"
)

func TestSecretSocketRevisionNamesTheReadSetOnly(t *testing.T) {
	a, b := socketRevision([32]byte{1}), socketRevision([32]byte{2})
	if a == b || a != socketRevision([32]byte{1}) || len(a) != 32 {
		t.Fatal(a, b)
	}
}

// An endpoint whose task this server no longer runs is closed and its
// socket removed; one whose task still runs stays.
func TestRetainSecretSocketsClosesTasksNoLongerHere(t *testing.T) {
	r := &Runtime{}
	open := func(key string) string {
		dir := t.TempDir()
		anchor, err := peercred.Open(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		e, err := sfev.Open(sfev.Config{Name: key, Dir: dir, Anchor: anchor, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Fetch: func(context.Context) (sfev.Snapshot, error) { return sfev.Snapshot{}, sfev.ErrDenied }, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		if r.secretSockets.open == nil {
			r.secretSockets.open = map[string]*secretSocket{}
		}
		r.secretSockets.open[key] = &secretSocket{endpoint: e, anchor: anchor}
		return filepath.Join(dir, sfev.SocketName)
	}
	kept, gone := open("workload/task/kept"), open("workload/task/gone")
	r.retainSecretSockets([]appWorkload{{step: deployment.Step{Key: "workload/task/kept", Kind: "task"}}, {step: deployment.Step{Key: "workload/task/gone", Kind: "inputs"}}})
	if _, err := os.Lstat(kept); err != nil {
		t.Fatal("running task's socket closed", err)
	}
	if _, err := os.Lstat(gone); !os.IsNotExist(err) {
		t.Fatal("socket of a task no longer here left open")
	}
	if len(r.secretSockets.open) != 1 {
		t.Fatal(len(r.secretSockets.open))
	}
	r.closeSecretSockets()
	if _, err := os.Lstat(kept); !os.IsNotExist(err) || len(r.secretSockets.open) != 0 {
		t.Fatal("closeSecretSockets left a socket")
	}
}
