// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// NodeStorageKey is physical storage policy, separate from StorageKey's
// receipt/ledger epoch. Both use the existing committed FSM/checkpoint path.
const NodeStorageKey = "control/node-storage"

type NodeStorageSelection struct{ Node, ID string }
type NodeStoragePolicy struct {
	Node, ID   string
	Tenants    []string
	MaxVolumes int
}

type NodeStorageWork struct {
	Root                       nodestorage.Root
	Epoch, RootRevision, Index uint64
}

func (p Policy) NodeStoragePage(s state.State, users access.Catalog, actor, node, after string) ([]nodestorage.Root, string, error) {
	if !users.SystemAllowed(actor) {
		return nil, "", access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nil, "", err
	}
	var page []nodestorage.Root
	for _, root := range roots.Roots() {
		key := root.Definition.Node + "/" + root.Definition.ID
		if node != "" && root.Definition.Node != node || key <= after {
			continue
		}
		if len(page) == 8 {
			last := page[len(page)-1]
			return page, last.Definition.Node + "/" + last.Definition.ID, nil
		}
		page = append(page, root)
	}
	return page, "", nil
}

func (p Policy) NodeStoragePermit(s state.State, caller [32]byte, q NodeStorageSelection) (NodeStorageWork, error) {
	roots, err := p.NodeStorage(s)
	if err != nil {
		return NodeStorageWork{}, err
	}
	r, ok := roots.Root(q.Node, q.ID)
	current, err := p.nodeOwner(s, q.Node)
	if !ok || err != nil || current != caller || !p.ownsResource(s, caller, r.Definition.Key) {
		return NodeStorageWork{}, access.ErrDenied
	}
	if r.Attestation == nil && !r.Draining {
		if active, err := p.workNodeOwner(s, q.Node); err != nil || active != caller {
			return NodeStorageWork{}, access.ErrDenied
		}
	}
	return NodeStorageWork{Root: r, Epoch: s.ModuleEpoch(), RootRevision: s.Object(NodeStorageKey).Revision, Index: s.Index()}, nil
}

func (p Policy) NodeStorageRead(s state.State, session access.Session, now int64, q NodeStorageSelection) (nodestorage.Root, error) {
	p, err := p.Current(s)
	if err != nil {
		return nodestorage.Root{}, err
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nodestorage.Root{}, err
	}
	if users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), now, "", access.ManageCluster, "") != nil {
		return nodestorage.Root{}, access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nodestorage.Root{}, err
	}
	root, ok := roots.Root(q.Node, q.ID)
	key, err := p.nodeOwner(s, q.Node)
	if !ok || err != nil || !p.ownsResource(s, key, root.Definition.Key) || root.Draining || root.Closed != nil || root.Attestation == nil {
		return nodestorage.Root{}, access.ErrDenied
	}
	return root, nil
}

func (p Policy) NodeStorage(s state.State) (nodestorage.Catalog, error) {
	raw, revision, err := readCheckpoint(s, NodeStorageKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return nodestorage.Catalog{}, err
	}
	if raw == nil {
		return nodestorage.New(p.Cluster)
	}
	roots, err := nodestorage.Decode(raw)
	if err != nil || roots.Cluster() != p.Cluster || roots.Revision() != revision || revision == 0 {
		return nodestorage.Catalog{}, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil {
		return nodestorage.Catalog{}, err
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nodestorage.Catalog{}, err
	}
	for _, root := range roots.Roots() {
		member, ok := members.Entry(root.Definition.Node)
		_, e := identity.ParseKey(member.CurrentPeer().Key)
		if !ok || e != nil || !members.ResourceKeyForNode(root.Definition.Node, root.Definition.Key) {
			return nodestorage.Catalog{}, ErrCatalog
		}
		for _, id := range root.Definition.Tenants {
			if _, ok := users.Tenant(id); !ok {
				return nodestorage.Catalog{}, ErrCatalog
			}
		}
	}
	return roots, nil
}

func (p Policy) nodeStorageCheckpoint(s state.State, roots nodestorage.Catalog) (map[string][]byte, state.Code) {
	raw, err := roots.Encode()
	if err != nil || roots.Cluster() != p.Cluster {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, NodeStorageKey, p.Cluster, p.TrustRoot, roots.Revision(), raw)
}

// Only the complete same-candidate Volume view may decide whether a root is
// unused. Terminal unregister tombstones keep their generation/fact history,
// but no longer reserve the physical root. Pending native work stays counted.
func registeredOnRoot(v Volumes, ref nodestorage.Reference) int {
	count := 0
	for _, entry := range v.entries {
		if entry.Native.Fixed != nil && entry.Native.Fixed.Root.Root == ref && !entry.State.Deleted() {
			count++
		}
	}
	for _, job := range v.creations {
		if job.Fixed != nil && creationPending(job.Phase) && job.Fixed.Root.Root == ref {
			count++
		}
	}
	return count
}

func (p Policy) canUseFixedVolume(s state.State, users access.Catalog, actor string, entry registeredVolume) error {
	if !entry.State.Fixed() {
		return nil
	}
	if entry.Native.Fixed == nil || entry.Native.Verify() != nil {
		return ErrCatalog
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return err
	}
	ref := entry.Native.Fixed.Root.Root
	root, err := roots.CanUse(users, actor, entry.State.Scope().Tenant, ref.Node, ref.ID, ref.Generation)
	if err != nil || root.Reference(p.Cluster) != ref {
		return access.ErrDenied
	}
	return nil
}

func (p Policy) validateFixedVolumes(roots nodestorage.Catalog, v Volumes) error {
	var registered []registeredVolume
	var selections []nodestorage.FixedSelection
	for _, entry := range v.entries {
		if !entry.State.Fixed() {
			if entry.Native.Fixed != nil {
				return ErrCatalog
			}
			continue
		}
		if entry.Native.Fixed == nil || entry.Native.Spec.Kind != "node-fixed" {
			return ErrCatalog
		}
		if entry.State.Deleted() {
			continue
		}
		fixed := entry.Native.Fixed
		ref := fixed.Root.Root
		root, ok := roots.Root(ref.Node, ref.ID)
		if !ok || root.Reference(p.Cluster) != ref || root.Attestation == nil || root.Closed != nil || !bytes.Equal(nodestorage.RootFactBytes(*root.Attestation), nodestorage.RootFactBytes(fixed.Root)) || registeredOnRoot(v, ref) > root.Definition.MaxVolumes {
			return ErrCatalog
		}
		// A revoked tenant ACL stops new use, but must not erase old data,
		// consumers or unregister work. Do not require current ACL here.
		for _, other := range registered {
			if other.Native.Spec.Node == entry.Native.Spec.Node && other.Native.Spec.NodeKey == entry.Native.Spec.NodeKey && fixed.Directory.Overlaps(other.Native.Fixed.Directory) {
				return ErrCatalog
			}
		}
		registered = append(registered, entry)
		selections = append(selections, fixed.Selection())
	}
	for _, job := range v.creations {
		if job.Fixed == nil || !creationPending(job.Phase) {
			continue
		}
		fixed := job.Fixed
		ref := fixed.Root.Root
		root, ok := roots.Root(ref.Node, ref.ID)
		if !ok || root.Reference(p.Cluster) != ref || root.Attestation == nil || root.Closed != nil || !bytes.Equal(nodestorage.RootFactBytes(*root.Attestation), nodestorage.RootFactBytes(fixed.Root)) || registeredOnRoot(v, ref) > root.Definition.MaxVolumes {
			return ErrCatalog
		}
		for _, other := range selections {
			if fixed.Overlaps(other) {
				return ErrCatalog
			}
		}
		selections = append(selections, fixed.Clone())
	}
	return nil
}

func (p Policy) authorizeNodeStorage(c access.Catalog, op UserOperation) error {
	switch op.Change.Action {
	case "add-node-storage", "set-node-storage-policy", "drain-node-storage", "remove-node-storage":
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	default:
		return access.ErrInvalid
	}
}

func (p Policy) reduceNodeStorage(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if (cmd.Kind != state.Module && cmd.Kind != state.ModuleReport) || cmd.Key != NodeStorageKey {
		return nil, state.Forbidden
	}
	if strings.HasPrefix(cmd.Actor, "node/") {
		if cmd.Kind != state.ModuleReport {
			return nil, state.Forbidden
		}
		return p.reduceNodeStorageReport(s, cmd)
	}
	if cmd.Kind != state.Module || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeNodeStorage(c, op) != nil {
		return nil, state.Forbidden
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nil, state.Invalid
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	switch op.Change.Action {
	case "add-node-storage":
		var definition nodestorage.Definition
		if canonical(op.Change.Payload, &definition) != nil {
			return nil, state.Invalid
		}
		key, e := p.workNodeOwner(s, definition.Node)
		if e != nil || definition.Key != ([32]byte{}) && definition.Key != key {
			return nil, state.Forbidden
		}
		definition.Key = key
		roots, err = roots.Add(c, op.Session.User, op.Change.Expected, definition)
	case "set-node-storage-policy":
		var q NodeStoragePolicy
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		root, ok := roots.Root(q.Node, q.ID)
		if !ok {
			return nil, state.ConditionFailed
		}
		roots, err = roots.SetPolicy(c, op.Session.User, q.Node, q.ID, op.Change.Expected, q.Tenants, q.MaxVolumes, registeredOnRoot(v, root.Reference(p.Cluster)))
	case "drain-node-storage", "remove-node-storage":
		var q NodeStorageSelection
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		root, ok := roots.Root(q.Node, q.ID)
		if !ok {
			return nil, state.ConditionFailed
		}
		if op.Change.Action == "drain-node-storage" {
			roots, err = roots.Drain(c, op.Session.User, q.Node, q.ID, op.Change.Expected)
		} else {
			builds, buildErr := p.ImageBuilds(s)
			if buildErr != nil {
				return nil, state.Invalid
			}
			roots, err = roots.Remove(c, op.Session.User, q.Node, q.ID, op.Change.Expected, registeredOnRoot(v, root.Reference(p.Cluster))+builds.RootReferences(root.Reference(p.Cluster)))
		}
	default:
		return nil, state.Invalid
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	return p.nodeStorageCheckpoint(s, roots)
}
