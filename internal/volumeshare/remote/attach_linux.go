// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/fdstore"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/front/mount"
	"github.com/jay94ks/seafield/internal/volumeshare/fuse"
	"golang.org/x/sys/unix"
)

// FUSE is the real Attach: it mounts the home's VolumeFS under base/<name>.
// call returns the VolumeFS call to a home (volumeshare.CallHome); sent is
// sfcp.CallSent.
//
// Each mount's /dev/fuse fd and node log go to the service manager's FD
// store (fdstore). When sfcd starts again with them, Attach resumes the
// same kernel mount instead of making a new one: the engine's clones in
// running containers keep working, and only files that were open on the
// home report EBADF (the home forgot the old VolumeFS session).
func FUSE(base string, call func(home [32]byte) volumeshare.Call, sent func(error) bool) Attach {
	// Inherited mounts whose home could not be reached yet wait here for
	// the next try; they are never replaced by a fresh mount meanwhile.
	var mu sync.Mutex
	waiting := map[string]inherited{}
	return func(ctx context.Context, spec Spec) (Attached, error) {
		if !filepath.IsAbs(base) || filepath.Clean(base) != base {
			return Attached{}, errors.New("remote volume: mount base is not a clean absolute path")
		}
		if err := os.MkdirAll(base, 0o700); err != nil {
			return Attached{}, err
		}
		name := spec.Name()
		dir := filepath.Join(base, name)
		mu.Lock()
		w, ok := waiting[name]
		delete(waiting, name)
		mu.Unlock()
		if !ok {
			var err error
			if w, err = inheritedMount(name); err != nil {
				return Attached{}, err
			}
		}
		dev, nodes, resumed := w.dev, w.nodes, w.dev != nil
		if !resumed {
			// A mount left by an earlier sfcd without a stored fd has no
			// server behind it any more.
			_ = unix.Unmount(dir, unix.MNT_DETACH)
			if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return Attached{}, err
			}
		}
		run, stop := context.WithCancel(context.Background())
		client, err := volumeshare.Dial(ctx, call(spec.Home), volumeshare.ClientOptions{Volume: spec.Ref().String(), Sent: sent})
		if err != nil {
			stop()
			if resumed {
				mu.Lock()
				waiting[name] = w
				mu.Unlock()
			}
			return Attached{}, err
		}
		pinged := make(chan struct{})
		go func() { defer close(pinged); client.Run(run) }()
		serve := fuse.ServeOptions{}
		if resumed {
			session := nodes.session
			serve.Resume = &session
		} else {
			dev, err = fuse.Mount(dir, fuse.MountOptions{Source: name, Subtype: "sfc", ReadOnly: !spec.Consumer.Writable})
			if err != nil {
				stop()
				<-pinged
				return Attached{}, err
			}
			if nodes, err = openNodeLog(name, fuse.Session{}); err != nil {
				stop()
				<-pinged
				_ = unix.Unmount(dir, 0)
				_ = dev.Close()
				return Attached{}, err
			}
			serve.OnInit = nodes.setSession
			if fdstore.Available() {
				if err := fdstore.Store(devName(name), dev.FD()); err != nil {
					log.Printf("shared volume %s: mount not kept across restarts: %v", name, err)
				}
			}
		}
		fs := mount.New(client, mount.Options{Session: client.Session(), EntryTTL: time.Second, AttrTTL: time.Second, Nodes: nodes, Restore: nodes.nodes()})
		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = fuse.Serve(run, dev, fs, serve)
		}()
		detach := func() error {
			if err := unix.Unmount(dir, 0); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
				return err
			}
			// The engine's clones of a gone container may outlive our mount
			// point; closing the device (here and in the store) ends the
			// connection for them too.
			if fdstore.Available() {
				_ = fdstore.Remove(devName(name))
			}
			nodes.close()
			stop()
			_ = dev.Close()
			<-served
			<-pinged
			_ = os.Remove(dir)
			return nil
		}
		abandon := func() {
			// What a crash does: our fds close, the stored ones stay.
			stop()
			<-served
			<-pinged
			_ = dev.Close()
			nodes.release()
		}
		return Attached{Dir: dir, Detach: detach, abandon: abandon}, nil
	}
}

// inheritedMount takes name's /dev/fuse fd and node log from the FD store,
// if an earlier sfcd left both.
type inherited struct {
	dev   *fuse.Device
	nodes *nodeLog
}

func inheritedMount(name string) (inherited, error) {
	devs := fdstore.Take(devName(name))
	nodes, err := inheritedLog(name)
	if len(devs) == 0 || nodes == nil || err != nil {
		for _, f := range devs {
			_ = f.Close()
		}
		if nodes != nil {
			nodes.release()
		}
		if len(devs) > 0 || nodes != nil {
			// Half a hand-off cannot resume; drop it from the store.
			_ = fdstore.Remove(devName(name))
			log.Printf("shared volume %s: stored mount not resumable: %v", name, err)
		}
		return inherited{}, nil
	}
	for _, f := range devs[1:] {
		_ = f.Close()
	}
	fd, err := unix.FcntlInt(devs[0].Fd(), unix.F_DUPFD_CLOEXEC, 0)
	_ = devs[0].Close()
	if err != nil {
		nodes.release()
		return inherited{}, err
	}
	dev, err := fuse.NewDevice(fd)
	if err != nil {
		unix.Close(fd)
		nodes.release()
		return inherited{}, err
	}
	return inherited{dev: dev, nodes: nodes}, nil
}
