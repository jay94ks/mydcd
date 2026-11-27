// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strconv"

	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/remote"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// openSharedVolumes serves this node's shared Volumes to their remote
// consumers (home) and keeps the remote Volumes of tasks here (runner).
// See devel/proposals/shared-volumes-over-sfcp.md.
func (r *Runtime) openSharedVolumes(stateDir string) error {
	if r.Mesh == nil || r.activations == nil {
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
