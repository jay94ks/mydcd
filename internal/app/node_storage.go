// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) observeNodeStorageSpace(ctx context.Context, root nodestorage.Root) (nodestorage.Space, error) {
	if root.Definition.Key != r.Identity.Public {
		return nodestorage.Space{}, sfcp.ErrAdmission
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	work, err := r.nodeStoragePermit(ctx, root)
	if err != nil || work.Root.Revision != root.Revision || work.Root.Draining || work.Root.Attestation == nil || work.Root.Closed != nil {
		return nodestorage.Space{}, errors.Join(nodestorage.ErrStorage, err)
	}
	r.life.RLock()
	if r.closed || r.nodeRoots == nil {
		r.life.RUnlock()
		return nodestorage.Space{}, sfcp.ErrAdmission
	}
	err = r.nodeRoots.Desired(work.Root)
	var value nodestorage.Space
	if err == nil {
		value, err = r.nodeRoots.Space(ctx, work.Root)
	}
	r.life.RUnlock()
	if err != nil {
		return nodestorage.Space{}, err
	}
	current, err := r.nodeStoragePermit(ctx, root)
	if err != nil || current.Root.Revision != root.Revision || current.Root.Draining || current.Root.Closed != nil {
		return nodestorage.Space{}, errors.Join(nodestorage.ErrStorage, err)
	}
	return value, nil
}

func (r *Runtime) nodeStorageSpace(ctx context.Context, root nodestorage.Root) (nodestorage.Space, error) {
	if owner, local := r.nativeOwner(root.Definition.Key); local {
		return owner.observeNodeStorageSpace(ctx, root)
	}
	peer, ok := r.resourcePeer(ctx, root.Definition.Node, root.Definition.Key)
	if !ok || !peer.Member || peer.ID != root.Definition.Node {
		return nodestorage.Space{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(root)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "node-storage-space-observe", Input: raw})
	if err != nil {
		return nodestorage.Space{}, err
	}
	value, err := schema.Decode[nodestorage.Space](reply.Data)
	if err != nil || value.Root != root.Reference(r.controlPolicy.Cluster) {
		return nodestorage.Space{}, errors.Join(nodestorage.ErrStorage, err)
	}
	return value, nil
}

func (r *Runtime) nodeStoragePermit(ctx context.Context, root nodestorage.Root) (control.NodeStorageWork, error) {
	return r.nodeStorageReferencePermit(ctx, root.Reference(r.controlPolicy.Cluster))
}

func (r *Runtime) nodeStorageReferencePermit(ctx context.Context, ref nodestorage.Reference) (control.NodeStorageWork, error) {
	if ref.Validate() != nil {
		return control.NodeStorageWork{}, nodestorage.ErrStorage
	}
	raw, _ := json.Marshal(control.NodeStorageSelection{Node: ref.Node, ID: ref.ID})
	reply, err := r.appCall(ctx, "node-storage-permit", raw)
	if err != nil {
		return control.NodeStorageWork{}, err
	}
	work, err := schema.Decode[control.NodeStorageWork](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || work.Index == 0 || work.Epoch == 0 || work.RootRevision == 0 || work.Root.Reference(r.controlPolicy.Cluster) != ref || work.Root.Definition.Key != r.Identity.Public {
		return work, errors.Join(nodestorage.ErrStorage, err)
	}
	return work, nil
}

func (r *Runtime) publishNodeStorage(ctx context.Context, work control.NodeStorageWork, report control.NodeStorageReport) error {
	report.Schema, report.Cluster, report.Reporter = 1, r.controlPolicy.Cluster, r.commandIdentity().Public
	report.Epoch, report.RootRevision, report.Expected = work.Epoch, work.RootRevision, work.Root.Revision
	report.Index = work.Index
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.NodeStorageReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "node-storage-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return nodestorage.ErrStorage
	}
	return nil
}

// defaultStoragePath is the default storage root of a node whose state lives
// in stateDir: its sibling "<state_dir>-storage" (/var/lib/sfc-storage for
// the usual /var/lib/sfc). It is outside the state directory so wiping the
// daemon state never deletes data kept there.
func defaultStoragePath(stateDir string) string {
	return filepath.Clean(stateDir) + "-storage"
}

// registerDefaultStorage registers this node's default storage root once:
// every tenant may use it and it has no capacity limit. It does nothing once
// the node has ever had a default root, so an operator who removes it (or
// changes it) keeps that choice across restarts and rejoins. A filesystem
// without a stable directory identity (not ext4) gets no default root.
func (r *Runtime) registerDefaultStorage(ctx context.Context, roots nodestorage.Catalog) error {
	self := r.defaultStorageNode
	if r.defaultStorageDone || r.defaultStorage == "" || self == "" {
		return nil
	}
	if _, ok := roots.Root(self, nodestorage.DefaultRootID); ok || roots.Registered(self, nodestorage.DefaultRootID) {
		r.defaultStorageDone = true
		return nil
	}
	if time.Now().Before(r.defaultStorageNext) {
		return nil
	}
	r.defaultStorageNext = time.Now().Add(time.Minute)
	if err := os.MkdirAll(r.defaultStorage, 0o755); err != nil {
		return fmt.Errorf("default storage %s: %w", r.defaultStorage, err)
	}
	h, err := nodestorage.OpenDirectory(r.defaultStorage)
	if err != nil {
		if errors.Is(err, nodestorage.ErrUnsupported) {
			log.Printf("default storage %s not registered: %v", r.defaultStorage, err)
			r.defaultStorageDone = true
			return nil
		}
		return fmt.Errorf("default storage %s: %w", r.defaultStorage, err)
	}
	_ = h.Close()
	raw, _ := json.Marshal(control.NodeStorageSelection{Node: self, ID: nodestorage.DefaultRootID})
	reply, err := r.appCall(ctx, "node-storage-permit", raw)
	if err != nil {
		return err
	}
	work, err := schema.Decode[control.NodeStorageWork](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || work.Index == 0 || work.Epoch == 0 {
		return errors.Join(nodestorage.ErrStorage, err)
	}
	if !work.Unregistered {
		r.defaultStorageDone = true
		return nil
	}
	d := nodestorage.DefaultDefinition(self, r.commandIdentity().Public, r.defaultStorage)
	if err = r.publishNodeStorage(ctx, work, control.NodeStorageReport{Action: "default", Default: &d}); err != nil {
		return fmt.Errorf("default storage %s: %w", r.defaultStorage, err)
	}
	r.defaultStorageDone = true
	return nil
}

func (r *Runtime) reconcileNodeStorage(ctx context.Context, view cluster.View) error {
	roots, err := r.controlPolicy.NodeStorage(view.State)
	if err != nil {
		return err
	}
	keys := map[string]bool{}
	// A failed default registration (leader unreachable, mkdir) must not stop
	// the other roots' reconciliation in this pass; it is retried later.
	failed := r.registerDefaultStorage(ctx, roots)
	for _, root := range roots.Roots() {
		if root.Definition.Key != r.Identity.Public {
			continue
		}
		key := nodestorage.RootNativeKey(root.Reference(r.controlPolicy.Cluster))
		keys[key] = true
		if r.nodeRoots == nil {
			return errors.New("node storage native journal unavailable")
		}
		settled, e := r.nodeRoots.Settled(ctx, root)
		if e != nil {
			failed = errors.Join(failed, fmt.Errorf("node storage %s original observation: %w", key, e))
			continue
		}
		if settled {
			continue
		}
		work, e := r.nodeStoragePermit(ctx, root)
		if e == nil {
			e = r.nodeRoots.Desired(work.Root)
		}
		if e == nil {
			e = r.nodeRoots.Step(ctx, key)
		}
		if e != nil {
			failed = errors.Join(failed, fmt.Errorf("node storage %s: %w", key, e))
			continue
		}
		if !work.Root.Draining && work.Root.Attestation != nil || work.Root.Closed != nil {
			continue
		}
		// Revalidate current policy after native inspection/settlement. A
		// newer Drain cannot be turned into Ready by an older observation.
		work, e = r.nodeStoragePermit(ctx, work.Root)
		if e == nil {
			e = r.nodeRoots.Desired(work.Root)
		}
		if e != nil {
			failed = errors.Join(failed, e)
			continue
		}
		if work.Root.Draining {
			closed, e := r.nodeRoots.Closed(work.Root)
			if e == nil {
				e = r.publishNodeStorage(ctx, work, control.NodeStorageReport{Action: "closed", Closed: &closed})
			}
			failed = errors.Join(failed, e)
		} else if work.Root.Attestation == nil {
			fact, e := r.nodeRoots.Fact(ctx, work.Root)
			if e == nil {
				e = r.publishNodeStorage(ctx, work, control.NodeStorageReport{Action: "registered", Ready: &fact})
			}
			failed = errors.Join(failed, e)
		}
		if ctx.Err() != nil {
			break
		}
	}
	if r.nodeRoots != nil {
		for _, key := range r.nodeRoots.Keys() {
			if keys[key] {
				continue
			}
			row, e := r.nodeRoots.View(key)
			if e != nil {
				failed = errors.Join(failed, e)
				continue
			}
			if row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || len(row.Consumers) != 0 {
				failed = errors.Join(failed, fmt.Errorf("node storage %s has unresolved original work without a committed root", key))
			}
		}
	}
	return failed
}
