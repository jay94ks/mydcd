// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
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
	r.sharedServer = volumeshare.NewServer(r.sharedHome.Authorize, volumeshare.ServerOptions{})
	if err := volumeshare.Serve(r.Mesh, r.sharedServer); err != nil {
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
// consumer left, fences the remote consumers whose runner left the cluster,
// and forgets released runner records whose consumer Raft has dropped. All
// only follow committed state; a failed read waits.
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
		if err := r.fenceGoneRunners(v); err != nil {
			log.Printf("shared volume: fence of a removed server's mount: %v", err)
		}
		r.remoteMounts.ForgetGone(func(s remote.Spec) bool {
			return !slices.Contains(consumers(s.Scope), s.Consumer)
		})
	}
}

// fenceGoneRunners releases the remote consumers of Volumes this node owns
// whose runner was removed or retired: that server can never sign Gone.
// The read already says it is gone, so Authorize refuses its mounts; Revoke
// then ends the sessions it still had and waits out their operations in
// flight, and only after that the owner key signs the fence. Each applied
// fence moves the Volumes root, so the next one is built on a new read.
func (r *Runtime) fenceGoneRunners(v cluster.View) error {
	mine := func(owner [32]byte) bool {
		_, ok := r.nativeOwner(owner)
		return ok
	}
	for range 64 {
		work, err := r.controlPolicy.VolumeRemoteFences(v.State, mine)
		if err != nil || len(work) == 0 {
			return err
		}
		w := work[0]
		owner, _ := r.nativeOwner(w.Owner)
		r.sharedServer.Revoke(remote.MountRef{Scope: w.Scope, Consumer: w.Consumer.ID}.String())
		proof := volumes.RemoteFence{Schema: 1, Scope: w.Scope, Consumer: w.Consumer}
		proof.Signature = ed25519.Sign(owner.Identity.Private, volumes.RemoteFenceBytes(proof))
		report := control.VolumeRemoteFenceReport{Schema: 1, Operation: "remote-fence", Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.VolumesKey).Revision, At: time.Now().Unix(), Proof: proof}
		raw, _ := json.Marshal(report)
		ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
		reply, err := r.appCall(ctx, "volume-remote-fence-report", raw)
		if err == nil && (reply.Committed == nil || reply.Committed.Result.Code != state.Applied) {
			err = errors.New("fence not applied")
		}
		if err == nil {
			v, err = r.Engine().Read(ctx, false)
		}
		cancel()
		if err != nil {
			// The next sweep reads again; a moved root revision only means
			// another change landed first.
			return err
		}
	}
	return nil
}
