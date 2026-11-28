// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/remote"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// openSharedVolumes serves this node's shared Volumes to their remote
// consumers (home) and keeps the remote Volumes of tasks here (runner).
// See devel/proposals/shared-volumes-over-sfcp.md.
//
// Only the current-key runtime serves them: a historical owner (an earlier
// node key, kept after a key rotation) shares the same transport, which
// takes one VolumeFS handler, so registering it again failed every start
// after a rotation.
func (r *Runtime) openSharedVolumes(stateDir string) error {
	if r.historicalOwner || r.Mesh == nil || r.activations == nil {
		return nil
	}
	r.sharedHome = remote.NewHome(r.remoteVolumeGrant, r.activations.ServedSource, r.volumeHandleKey)
	if err := volumeshare.Serve(r.Mesh, volumeshare.NewServer(r.sharedHome.Authorize, volumeshare.ServerOptions{})); err != nil {
		return err
	}
	db, err := storage.Open(filepath.Join(stateDir, "workload", "remote-volumes.db"))
	if err != nil {
		return err
	}
	r.remoteMounts, err = remote.Open(db, remote.FUSE(filepath.Join(stateDir, "workload", "remote-volumes"), func(home [32]byte) volumeshare.Call {
		return volumeshare.CallHome(r.Mesh, sfcp.Identity(home))
	}, sfcp.CallSent))
	if err != nil {
		_ = db.Close()
		return err
	}
	r.remoteJournal = db
	r.remoteVolumes = r.remoteMounts
	// Mounts an earlier sfcd left in the FD store are served again now:
	// running containers are waiting on them.
	r.remoteMounts.Resume(r.ctx)
	go r.sweepSharedVolumes()
	return nil
}

// remoteVolumeGrant decides a VolumeFS mount on a local read: the home
// rechecks every few seconds and on every change, so a stale read is
// bounded by that, and revocation needs only the next applied index.
func (r *Runtime) remoteVolumeGrant(ctx context.Context, peer [32]byte, ref remote.MountRef) (volumes.Consumer, volumes.NativeReady, error) {
	e := r.Engine()
	if e == nil {
		return volumes.Consumer{}, volumes.NativeReady{}, errors.New("shared volume: cluster not open")
	}
	v, err := e.Read(ctx, false)
	if err != nil {
		return volumes.Consumer{}, volumes.NativeReady{}, err
	}
	return r.controlPolicy.VolumeRemoteGrant(v.State, r.Identity.Public, peer, ref.Scope, ref.Consumer)
}

// volumeHandleKey seals a Volume's VolumeFS handles with a key only this
// node can derive, stable across restarts and distinct per generation.
func (r *Runtime) volumeHandleKey(ready volumes.NativeReady) []byte {
	m := hmac.New(sha256.New, r.Identity.Private.Seed())
	m.Write([]byte("sfc volumefs handles\x00" + volumes.NativeKey(ready.Spec) + "\x00" + strconv.FormatUint(ready.Generation, 10)))
	return m.Sum(nil)
}

// sweepSharedVolumes stops serving Volume generations with no remote
// consumer left and forgets released runner records whose consumer Raft
// has dropped. Both only follow committed state; a failed read waits.
func (r *Runtime) sweepSharedVolumes() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
		}
		e := r.Engine()
		if e == nil {
			continue
		}
		read := time.Now()
		ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
		v, err := e.Read(ctx, false)
		cancel()
		if err != nil {
			continue
		}
		books, err := r.controlPolicy.Volumes(v.State)
		if err != nil {
			continue
		}
		consumers := func(scope volumes.Scope) []volumes.Consumer {
			s, ok := books.Volume(scope)
			if !ok {
				return nil
			}
			return s.Consumers()
		}
		r.sharedHome.Sweep(read, func(ready volumes.NativeReady) bool {
			for _, c := range consumers(ready.Spec.Scope) {
				if c.Remote() {
					return true
				}
			}
			return false
		})
		r.remoteMounts.ForgetGone(func(s remote.Spec) bool {
			return !slices.Contains(consumers(s.Scope), s.Consumer)
		})
	}
}
