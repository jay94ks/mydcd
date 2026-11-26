// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/workload"
)

func (r *Runtime) commandIdentity() *identity.Identity {
	if r.controlIdentity != nil {
		return r.controlIdentity
	}
	return r.Identity
}
func (r *Runtime) physicalWorkloads() []*workload.Manager {
	out := []*workload.Manager{}
	for _, owner := range r.physicalOwners() {
		out = append(out, owner.workload)
	}
	return out
}
func (r *Runtime) physicalOwners() []*Runtime {
	if r.parentRuntime != nil {
		return r.parentRuntime.physicalOwners()
	}
	r.nativeOwnerMu.RLock()
	defer r.nativeOwnerMu.RUnlock()
	return append([]*Runtime{r}, r.nativeOwners...)
}

// Historical owners share the one logical daemon/Engine/transport. Their finite
// original native journals, source signatures and sealed projection stores stay
// in the original namespace. They cannot authenticate or allocate a new old-key
// task: compiler placement uses CurrentPeer and every effect consumes its exact
// retained source through the current-key permit.
func (r *Runtime) openHistoricalOwners(effective, original config.Node, record bootstrap.Record, peers map[mydcp.Identity]mydcp.Peer) error {
	seen := map[[32]byte]bool{r.Identity.Public: true}
	for _, transition := range record.Root.Keys {
		key := transition.Proof.Old
		if seen[key] {
			continue
		}
		seen[key] = true
		path, ok := bootstrap.OwnerIdentityPath(original, record, key)
		if !ok {
			return bootstrap.ErrInstallation
		}
		ownerIdentity, err := identity.Load(path)
		if err != nil {
			return err
		}
		owner := &Runtime{parentRuntime: r, Identity: ownerIdentity, controlIdentity: r.Identity, historicalOwner: true, Mesh: r.Mesh, engine: r.Engine(), policy: r.policy, controlPolicy: r.controlPolicy, owner: desired.Owner(r.controlPolicy.Cluster, key), networkEnabled: r.networkEnabled, installation: r.installation, credentials: r.credentials, gitFetcher: r.gitFetcher, gitCredentials: r.gitCredentials, vaultBackends: r.vaultBackends, vaultApprovalBudget: r.vaultApprovalBudget}
		owner.ctx, owner.cancel = context.WithCancel(r.ctx)
		owner.checkerSourceBudget = r.checkerSourceBudget
		c := effective
		c.Node.IdentityDir = path
		c.Node.StateDir = bootstrap.NativeOwnerPath(original, record, key)
		owner.nativeRoot = c.Node.StateDir
		if err = owner.openModules(c, peers); err != nil {
			return errors.Join(err, owner.Close())
		}
		// Mesh is already listening. Publish only fully initialized native
		// owners; packet/path dispatch must never race module assignment.
		r.nativeOwnerMu.Lock()
		r.nativeOwners = append(r.nativeOwners, owner)
		r.nativeOwnerMu.Unlock()
	}
	// Current tasks consume the ORIGINAL native journal/gate through a local
	// adapter, while all transport and control commands keep the current key.
	for _, owner := range r.physicalOwners()[1:] {
		if r.network != nil && owner.network != nil {
			if err := r.network.AttachRetained(owner.network); err != nil {
				return err
			}
		}
		if r.activations != nil && owner.activations != nil {
			if err := r.activations.AttachRetained(owner.activations); err != nil {
				return err
			}
		}
	}
	for _, owner := range r.physicalOwners() {
		if owner.moduleStart != nil {
			start := owner.moduleStart
			owner.moduleStart = nil
			if err := start(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runtime) nativeOwner(key [32]byte) (*Runtime, bool) {
	if r.historicalOwner && r.parentRuntime != nil {
		return r.parentRuntime.nativeOwner(key)
	}
	if r.Identity.Public == key {
		return r, true
	}
	for _, owner := range r.physicalOwners()[1:] {
		if owner.Identity.Public == key {
			return owner, true
		}
	}
	return nil, false
}
func (r *Runtime) resourcePeer(ctx context.Context, node string, original [32]byte) (mydcp.Peer, bool) {
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return mydcp.Peer{}, false
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.ResourceKeyForNode(node, original) {
		return mydcp.Peer{}, false
	}
	entry, ok := members.Entry(node)
	if !ok {
		return mydcp.Peer{}, false
	}
	key, err := identity.ParseKey(entry.CurrentPeer().Key)
	if err != nil || !members.MemberKey(key) {
		return mydcp.Peer{}, false
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(key))
	return peer, ok && peer.Member && peer.ID == node
}

func (r *Runtime) acceptsResourceOwner(ctx context.Context, node string, key [32]byte) bool {
	if r.installation == nil || node != r.installation.record.Root.Self.ID {
		return false
	}
	peer, ok := r.resourcePeer(ctx, node, key)
	return ok && [32]byte(peer.Key) == r.commandIdentity().Public
}

// resourcePeerForKey is routing for an exact retained fact/use/job. Only the
// current peer is dialed; the original key remains in the resource and proofs.
func (r *Runtime) resourcePeerForKey(ctx context.Context, original [32]byte) (mydcp.Peer, bool) {
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return mydcp.Peer{}, false
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil {
		return mydcp.Peer{}, false
	}
	for _, entry := range members.Entries {
		if members.ResourceKeyForNode(entry.Peer.ID, original) {
			return r.resourcePeer(ctx, entry.Peer.ID, original)
		}
	}
	return mydcp.Peer{}, false
}
func (r *Runtime) resourceCaller(ctx context.Context, current, original [32]byte) bool {
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return false
	}
	members, err := r.controlPolicy.Members(view.State)
	return err == nil && members.OwnsResource(current, original)
}
func (r *Runtime) acceptsResourceKey(ctx context.Context, original [32]byte) bool {
	peer, ok := r.resourcePeerForKey(ctx, original)
	return ok && [32]byte(peer.Key) == r.commandIdentity().Public
}
