// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload"
	"time"
)

// nodeRead serves one node-to-node Management read (cluster nodeMethods)
// on this node. life runs it under the runtime's lifecycle lock with a
// context the runtime's own shutdown cancels.
type nodeRead struct {
	fn   func(*Runtime, context.Context, string, string, []byte, cluster.View) (json.RawMessage, error)
	life bool
}

// nodeReads is filled by each feature's *_node_reads.go file. Adding a node
// read means one entry in cluster.nodeMethods and one defineNodeRead next to
// the feature.
var nodeReads = map[string]nodeRead{}

func defineNodeRead(fn func(*Runtime, context.Context, string, string, []byte, cluster.View) (json.RawMessage, error), life bool, methods ...string) {
	for _, m := range methods {
		if _, dup := nodeReads[m]; dup {
			panic("duplicate node read " + m)
		}
		nodeReads[m] = nodeRead{fn, life}
	}
}

func (r *Runtime) readModule(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	h, found := nodeReads[method]
	if found && !h.life {
		return h.fn(r, ctx, method, key, input, v)
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil {
		return nil, errors.New("node is closing")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if found {
		return h.fn(r, ctx, method, key, input, v)
	}
	if method != "observe" || len(input) != 0 {
		return nil, errors.New("invalid local observation")
	}
	return r.observeManaged(ctx, key, v)
}

func init() {
	defineNodeRead((*Runtime).nodeReadVpsStatus, false, "vps-status")
	defineNodeRead((*Runtime).nodeReadNodeShellOwnerView, false, "node-shell-owner-view")
	defineNodeRead((*Runtime).nodeReadNodeShellPermit, false, "node-shell-permit")
	defineNodeRead((*Runtime).nodeReadNodeIdentityActivation, false, "node-identity-activation")
	defineNodeRead((*Runtime).nodeReadServiceCallPermit, false, "service-call-permit")
	defineNodeRead((*Runtime).nodeReadLifecycleSourceVersionPermit, false, "lifecycle-source-version-permit", "lifecycle-source-version-owner")
	defineNodeRead((*Runtime).nodeReadNodeDiagnosticsPermit, false, "node-diagnostics-permit", "node-diagnostics-owner")
	defineNodeRead((*Runtime).nodeReadNodeDisk, false, "node-disk-permit", "node-disk-owner")
	defineNodeRead((*Runtime).nodeReadNodeFirewall, false, "node-firewall-permit", "node-firewall-owner")
	defineNodeRead((*Runtime).nodeReadEventReceipt, false, "event-receipt")
	defineNodeRead((*Runtime).nodeReadNodeRuntimeWork, false, "node-runtime-work")
	defineNodeRead((*Runtime).nodeReadTenantRetirementWork, false, "tenant-retirement-work")
	defineNodeRead((*Runtime).nodeReadAppDeliverySyncWork, false, "app-delivery-sync-work")
	defineNodeRead((*Runtime).nodeReadAppDeliveryPermit, false, "app-delivery-permit")
	defineNodeRead((*Runtime).nodeReadContainerSessionPlan, false, "container-session-plan", "container-session-permit")
	defineNodeRead((*Runtime).nodeReadTunnelReconnectWork, false, "tunnel-reconnect-work")
	defineNodeRead((*Runtime).nodeReadCompactWork, false, "compact-work")
	defineNodeRead((*Runtime).nodeReadTaskRestartPermit, false, "task-restart-permit")
	defineNodeRead((*Runtime).nodeReadIngressObserve, false, "ingress-observe")
	defineNodeRead((*Runtime).nodeReadLoginRecordsObserve, false, "login-records-observe")
	defineNodeRead((*Runtime).nodeReadContainerReadPermit, false, "container-read-permit", "container-observe")
	defineNodeRead((*Runtime).nodeReadNodeStoragePermit, false, "node-storage-permit")
	defineNodeRead((*Runtime).nodeReadNodeStorageSpaceObserve, false, "node-storage-space-observe")
	defineNodeRead((*Runtime).nodeReadPlan, true, "plan")
}

func (r *Runtime) nodeReadVpsStatus(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	// Leader memory only; the asking node checked the user session.
	if !r.Engine().IsLeader() {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(r.vpsWatchStatus())
}

func (r *Runtime) nodeReadNodeShellOwnerView(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.nodeShellOwnerRead(key, input, v)
}

func (r *Runtime) nodeReadNodeShellPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.nodeShellPermitRead(key, input, v)
}

func (r *Runtime) nodeReadNodeIdentityActivation(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.NodeIdentityChange](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	activation, err := r.controlPolicy.ObserveIdentityActivation(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(activation)
}

func (r *Runtime) nodeReadServiceCallPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	read, cause := schema.Decode[control.ServiceCallRead](input)
	if err != nil || cause != nil || v.Local || read.Request.Body != nil {
		return nil, sfcp.ErrAdmission
	}
	index, err := r.controlPolicy.ServiceCallPermit(v.State, caller, read, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return json.Marshal(index)
}

func (r *Runtime) nodeReadLifecycleSourceVersionPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.lifecycleSourceModule(ctx, method, key, input, v)
}

func (r *Runtime) nodeReadNodeDiagnosticsPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.NodeDiagnosticsRead](input)
	d, memberErr := r.controlPolicy.Members(v.State)
	if err != nil || decodeErr != nil || memberErr != nil || !d.MemberKey(caller) {
		return nil, sfcp.ErrAdmission
	}
	if method == "node-diagnostics-owner" {
		result, err := r.nodeDiagnosticsLocal(ctx, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	read, err := r.controlPolicy.ReadNodeDiagnostics(v.State, q.Session, time.Now().Unix(), q.Node)
	if err != nil || v.Local || read.Owner != caller {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(read)
}

func (r *Runtime) nodeReadEventReceipt(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.eventReceipt(key, input, v)
}

func (r *Runtime) nodeReadNodeRuntimeWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	if err != nil || v.Local || string(input) != "{}" {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.NodeRuntimeWork(v.State, caller)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadTenantRetirementWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	request, decodeErr := schema.Decode[control.TenantID](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.TenantRetirementWork(v.State, caller, request.ID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadAppDeliverySyncWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	request, decodeErr := schema.Decode[control.AppDeliveryWorkRequest](input)
	now := uint64(time.Now().Unix())
	if err != nil || decodeErr != nil || v.Local || request.At == 0 || !access.Recent(request.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.AppDeliverySyncWork(v.State, caller, request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadAppDeliveryPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	request, decodeErr := schema.Decode[control.AppDeliveryRequest](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	permit, err := r.controlPolicy.AppDeliveryPermit(v.State, caller, request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadContainerSessionPlan(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.containerSessionRead(ctx, method, key, input, v)
}

func (r *Runtime) nodeReadTunnelReconnectWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.TunnelWorkRequest](input)
	if err != nil {
		return nil, err
	}
	work, err := r.controlPolicy.TunnelWork(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadCompactWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.CompactWorkRequest](input)
	if err != nil {
		return nil, err
	}
	_, leader := r.Engine().Leader()
	work, err := r.controlPolicy.CompactWork(v.State, caller, q, string(leader))
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadTaskRestartPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.taskRestartRead(key, input, v)
}

func (r *Runtime) nodeReadIngressObserve(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.ingressReadModule(ctx, key, input)
}

func (r *Runtime) nodeReadLoginRecordsObserve(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.loginRecordsObserve(key, input, v)
}

func (r *Runtime) nodeReadContainerReadPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	return r.containerReadModule(ctx, method, key, input, v)
}

func (r *Runtime) nodeReadNodeStoragePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	selection, err := schema.Decode[control.NodeStorageSelection](input)
	if err != nil {
		return nil, err
	}
	work, err := r.controlPolicy.NodeStoragePermit(v.State, caller, selection)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

// The native read obtains its own quorum permits and must not hold the
// lifecycle lock while calling back into the leader's read module.
func (r *Runtime) nodeReadNodeStorageSpaceObserve(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	root, err := schema.Decode[nodestorage.Root](input)
	if err != nil {
		return nil, err
	}
	owner, local := r.nativeOwner(root.Definition.Key)
	if !local {
		return nil, sfcp.ErrAdmission
	}
	value, err := owner.observeNodeStorageSpace(ctx, root)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func (r *Runtime) nodeReadPlan(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	in, err := schema.Decode[workload.PlacementInput](input)
	if err != nil {
		return nil, err
	}
	rows, err := r.reports.Scan("node/")
	if err != nil {
		return nil, err
	}
	nodes := make([]workload.Node, 0, len(rows))
	for _, id := range desired.Sorted(rows) {
		report, e := workload.DecodeReport(rows[id])
		if e != nil {
			return nil, e
		}
		nodes = append(nodes, report.Node)
	}
	plan, err := r.policy.Plan(v.State, in, nodes, uint64(time.Now().UnixMilli()), reportAge)
	if err != nil {
		return nil, err
	}
	return json.Marshal(plan)
}
