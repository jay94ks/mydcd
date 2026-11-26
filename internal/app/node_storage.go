// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) observeNodeStorageSpace(ctx context.Context, root nodestorage.Root) (nodestorage.Space, error) {
	if root.Definition.Key != r.Identity.Public {
		return nodestorage.Space{}, mydcp.ErrAdmission
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
		return nodestorage.Space{}, mydcp.ErrAdmission
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
		return nodestorage.Space{}, mydcp.ErrAdmission
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

func (r *Runtime) reconcileNodeStorage(ctx context.Context, view cluster.View) error {
	roots, err := r.controlPolicy.NodeStorage(view.State)
	if err != nil {
		return err
	}
	keys := map[string]bool{}
	var failed error
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
