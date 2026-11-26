// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"maps"
	"slices"
	"strings"
	"time"
)

// JournalView keeps the management response bounded without duplicating up to
// three full specs. get returns Shared bytes; Retirement is one canonical spec.
type ResourceView struct {
	Present    bool
	Generation uint64
	SpecSHA256 [32]byte
}
type JournalView struct {
	DesiredRevision, Retiring, GenerationFloor, LastID uint64
	Desired, Applied                                   ResourceView
	PendingID                                          uint64
	PendingKind                                        reconcile.Kind
	PendingPhase                                       reconcile.Phase
	Consumers, Capacity                                int
	Pins                                               map[string]reconcile.Lease `json:",omitempty"`
}
type ModuleObservation struct {
	NetworkClosure           *control.NetworkClosureStatus `json:",omitempty"`
	CheckerRuns              []checkerRunObservation       `json:",omitempty"`
	CheckerRunsTotal         int                           `json:",omitempty"`
	CheckerError             string                        `json:",omitempty"`
	DNS                      *DNSObservation               `json:",omitempty"`
	Ingress                  *ingress.Observation          `json:",omitempty"`
	Tunnel                   *TunnelObservation            `json:",omitempty"`
	Schema                   uint8
	Key                      string
	Revision, Generation     uint64
	Local, Ready             bool
	NativeID, Error          string
	Journal                  JournalView
	Retirement               json.RawMessage   `json:",omitempty"`
	Report                   *workload.Report  `json:",omitempty"`
	ModuleError, ReportError string            `json:",omitempty"`
	VolumeError              string            `json:",omitempty"`
	ReportDeliveryErrors     map[string]string `json:",omitempty"`
}

// This is a bounded view of existing local checker rows, not another result
// store. Native readiness remains independent of these diagnostic fields.
type checkerRunObservation struct {
	Checker    string
	RunID      string
	Status     string
	Reason     string
	At         int64
	Diagnostic checkerRunDiagnostic
}

func (r *Runtime) taskCheckerRuns(task deployment.ObjectRef) ([]checkerRunObservation, int, error) {
	parts := strings.Split(task.Key, "/")
	if r.reports == nil || len(parts) != 5 || parts[0] != "workload" || parts[1] != "task" {
		return nil, 0, nil
	}
	rows, err := r.reports.ScanBounded(checkerObservationPrefix+parts[2]+"/"+parts[3]+"/", maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return nil, 0, err
	}
	var out []checkerRunObservation
	for _, raw := range rows {
		point, err := schema.Decode[checkerObservation](raw)
		if err != nil || point.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
			return nil, 0, checker.ErrContract
		}
		if point.Task != task || point.Diagnostic == nil || point.Checkpoint.Last == nil {
			continue
		}
		o := point.Checkpoint.Last
		out = append(out, checkerRunObservation{Checker: o.Run.Request.Checker, RunID: o.Run.Request.RunID, Status: string(o.Result.Status), Reason: o.Result.Reason, At: o.At, Diagnostic: *point.Diagnostic})
	}
	slices.SortFunc(out, func(a, b checkerRunObservation) int {
		if a.At > b.At {
			return -1
		}
		if a.At < b.At {
			return 1
		}
		return strings.Compare(a.Checker, b.Checker)
	})
	total := len(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out, total, nil
}

// Compact current native DNS status. Views/query payloads and history stay in
// the owner DB, keeping management responses bounded.
type DNSObservation struct {
	Resolvers                  []string `json:",omitempty"`
	Desired, Applied, Observed uint64
	Queries, Sockets           int
	Stopped, Failed            bool
	QueryFailures              uint64 `json:",omitempty"`
	LastQueryError             string `json:",omitempty"`
}

func compact(r reconcile.Record) JournalView {
	view := func(r reconcile.Resource) ResourceView {
		return ResourceView{Present: r.Present, Generation: r.Generation, SpecSHA256: sha256.Sum256([]byte(r.Spec))}
	}
	j := JournalView{DesiredRevision: r.State.Desired.Revision, Retiring: r.State.Desired.Retiring, GenerationFloor: r.State.GenerationFloor, LastID: r.State.LastID, Desired: view(r.State.Desired.Resource), Applied: view(r.State.Applied), Consumers: len(r.Consumers), Capacity: r.Capacity}
	j.Pins = maps.Clone(r.Consumers)
	if p := r.State.Pending; p != nil {
		j.PendingID = p.ID
		j.PendingKind = p.Kind
		j.PendingPhase = p.Phase
	}
	return j
}
func (r *Runtime) readModule(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if method == "app-observation-renew" {
		return r.admitObservationRenewal(input, v)
	}
	if method == "node-shell-owner-view" {
		return r.nodeShellOwnerRead(key, input, v)
	}
	if method == "node-shell-permit" {
		return r.nodeShellPermitRead(key, input, v)
	}
	if method == "node-identity-activation" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.NodeIdentityChange](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		activation, err := r.controlPolicy.ObserveIdentityActivation(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(activation)
	}
	if method == "service-call-permit" {
		caller, err := identity.ParseKey(key)
		read, cause := schema.Decode[control.ServiceCallRead](input)
		if err != nil || cause != nil || v.Local || read.Request.Body != nil {
			return nil, mydcp.ErrAdmission
		}
		index, err := r.controlPolicy.ServiceCallPermit(v.State, caller, read, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		return json.Marshal(index)
	}
	if method == "lifecycle-source-version-permit" || method == "lifecycle-source-version-owner" {
		return r.lifecycleSourceModule(ctx, method, key, input, v)
	}
	if method == "node-diagnostics-permit" || method == "node-diagnostics-owner" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.NodeDiagnosticsRead](input)
		d, memberErr := r.controlPolicy.Members(v.State)
		if err != nil || decodeErr != nil || memberErr != nil || !d.MemberKey(caller) {
			return nil, mydcp.ErrAdmission
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
			return nil, mydcp.ErrAdmission
		}
		return json.Marshal(read)
	}

	if method == "image-build-publication-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		q, err := schema.Decode[control.ImageBuildPublicationQuery](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		result, err := r.imageBuildPublicationOwner(ctx, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if method == "image-build-secret-inputs" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildSecretRequest](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		q.At = time.Now().Unix()
		work, err := r.controlPolicy.ImageBuildSecretInputs(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "image-build-registry-permit" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildRegistryRequest](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		q.At = time.Now().Unix()
		permit, err := r.controlPolicy.ImageBuildRegistryPermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "image-build-base-work" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildBaseQuery](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		q.At = time.Now().Unix()
		read, err := r.controlPolicy.ImageBuildBaseRead(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(read)
	}
	if method == "image-build-base-tls-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		read, decodeErr := schema.Decode[control.ImageBuildBaseRead](input)
		if err != nil || decodeErr != nil || !known || !peer.Member || read.Builder != caller {
			return nil, mydcp.ErrAdmission
		}
		trust, err := r.imageBuildBaseTrustOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(trust)
	}
	if method == "image-build-registry-tls-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		permit, decodeErr := schema.Decode[control.ImageBuildRegistryPermit](input)
		if err != nil || decodeErr != nil || !known || !peer.Member || permit.Subject.Node != caller {
			return nil, mydcp.ErrAdmission
		}
		trust, err := r.imageBuildRegistryTrustOwner(ctx, permit)
		if err != nil {
			return nil, err
		}
		return json.Marshal(trust)
	}
	if method == "image-build-base-token-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		q, decodeErr := schema.Decode[control.ImageBuildBaseTokenRequest](input)
		if err != nil || decodeErr != nil || !known || !peer.Member || q.Read.Builder != caller {
			return nil, mydcp.ErrAdmission
		}
		token, err := r.imageBuildBaseTokenOwner(ctx, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(token)
	}
	if method == "image-build-base-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		read, decodeErr := schema.Decode[control.ImageBuildBaseRead](input)
		if err != nil || decodeErr != nil || !known || !peer.Member || read.Builder != caller {
			return nil, mydcp.ErrAdmission
		}
		result, err := r.resolveImageBuildBaseOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if method == "image-build-cache-prune-work" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildCachePruneWorkQuery](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		q.At = time.Now().Unix()
		work, err := r.controlPolicy.ImageBuildCachePruneWork(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "image-build-job-work" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildJobWorkQuery](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		q.At = time.Now().Unix()
		work, err := r.controlPolicy.ImageBuildJobWork(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "image-build-caches-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.ImageBuildCacheInventoryRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.imageBuildCacheInventoryOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "image-build-cache-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.ImageBuildCacheRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.imageBuildCacheOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "image-build-logs-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.ImageBuildLogRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.imageBuildLogsOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "image-build-content-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.ImageBuildContentRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.imageBuildContentOwner(ctx, read)
		if read.Query.Part == "file" {
			reply := imageBuildFileOwnerReply{Code: imageBuildFileReadCode(err)}
			if err == nil {
				reply.Content = &out
			}
			return json.Marshal(reply)
		}
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "image-build-git-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		call, err := schema.Decode[control.ImageBuildGitCall](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.saveImageBuildGitOwner(ctx, call)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "image-build-draft-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		call, err := schema.Decode[control.ImageBuildDraftCall](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.imageBuildDraftOwner(ctx, call)
		if call.Request.Kind == "file" {
			reply := imageBuildFileOwnerReply{Code: imageBuildFileReadCode(err)}
			if err == nil {
				reply.Draft = &out
			}
			return json.Marshal(reply)
		}
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "image-build-source-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.ImageBuildSourceRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.checkImageBuildSourceOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "image-build-artifact-work" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildArtifactSelection](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.ImageBuildArtifactWork(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "image-build-part-permit" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildPartPermitCall](input)
		now := time.Now().Unix()
		if err != nil || decodeErr != nil || v.Local || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.ImageBuildPartPermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "image-build-io-permit" {
		caller, err := identity.ParseKey(key)
		q, decodeErr := schema.Decode[control.ImageBuildIOCall](input)
		now := time.Now().Unix()
		if err != nil || decodeErr != nil || v.Local || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.ImageBuildIOPermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "image-build-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		q, err := schema.Decode[control.ImageBuildIOCall](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		out, err := r.imageBuildTransferOwner(ctx, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
	if method == "event-receipt" {
		return r.eventReceipt(key, input, v)
	}
	if method == "node-runtime-work" {
		caller, err := identity.ParseKey(key)
		if err != nil || v.Local || string(input) != "{}" {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.NodeRuntimeWork(v.State, caller)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "tenant-retirement-work" {
		caller, err := identity.ParseKey(key)
		request, decodeErr := schema.Decode[control.TenantID](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.TenantRetirementWork(v.State, caller, request.ID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "app-delivery-sync-work" {
		caller, err := identity.ParseKey(key)
		request, decodeErr := schema.Decode[control.AppDeliveryWorkRequest](input)
		now := uint64(time.Now().Unix())
		if err != nil || decodeErr != nil || v.Local || request.At == 0 || request.At > now || now-request.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.AppDeliverySyncWork(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "app-delivery-permit" {
		caller, err := identity.ParseKey(key)
		request, decodeErr := schema.Decode[control.AppDeliveryRequest](input)
		if err != nil || decodeErr != nil || v.Local {
			return nil, mydcp.ErrAdmission
		}
		permit, err := r.controlPolicy.AppDeliveryPermit(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "route-flow-observe" {
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		return r.observeRouteFlow(ctx, caller, input)
	}
	if method == "route-native-permit" {
		caller, err := identity.ParseKey(key)
		request, decodeErr := schema.Decode[control.RouteNativeRequest](input)
		now := time.Now().Unix()
		if err != nil || decodeErr != nil || v.Local || request.At <= 0 || request.At > now || now-request.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		permit, err := r.controlPolicy.RouteNativePermit(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "route-work" {
		caller, err := identity.ParseKey(key)
		request, decodeErr := schema.Decode[control.RouteWorkRequest](input)
		now := time.Now().Unix()
		if err != nil || decodeErr != nil || v.Local || request.At <= 0 || request.At > now || now-request.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.RouteWork(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "external-registry-work" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.ExternalRegistryWorkRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At <= 0 || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.ExternalRegistryWork(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "registry-image-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.RegistryImageRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At <= 0 || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		permit, err := r.controlPolicy.RegistryImagePermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}

	if method == "registry-work" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.RegistryWorkRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At <= 0 || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		work, err := r.controlPolicy.RegistryWork(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "checker-cache-observe" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		q, err := schema.Decode[control.CheckerArtifactRequest](input)
		if err != nil {
			return nil, err
		}
		observation, err := r.observeCheckerCache(ctx, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(observation)
	}
	if method == "checker-build-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.CheckerBuildRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		permit, err := r.controlPolicy.CheckerBuildPermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "checker-artifact-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.CheckerArtifactRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		permit, err := r.controlPolicy.CheckerArtifactPermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "checker-cache-gc-fence" {
		if v.Local || len(input) != 0 {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		directory, err := r.controlPolicy.Members(v.State)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(directory.Issuers(), caller) {
			return nil, mydcp.ErrAdmission
		}
		return json.Marshal(checkerCacheFence{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: caller, Index: v.State.Index(), Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.LifecycleKey).Revision})
	}
	if method == "checker-source-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.LifecycleSourcePermitRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		permit, err := r.controlPolicy.LifecycleSourcePermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "container-session-plan" || method == "container-session-permit" {
		return r.containerSessionRead(ctx, method, key, input, v)
	}
	if method == "image-cache-native-plan" {
		read, err := schema.Decode[control.ImageCacheRead](input)
		if err != nil {
			return nil, err
		}
		plan, err := r.nativeImageCachePlan(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(plan)
	}
	if method == "registry-maintenance-work" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.RegistryMaintenanceWorkRequest](input)
		if err != nil {
			return nil, err
		}
		work, err := r.controlPolicy.RegistryMaintenanceWork(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "image-cache-work" || method == "image-cache-plan-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		if method == "image-cache-work" {
			q, err := schema.Decode[control.ImageCacheWorkRequest](input)
			if err != nil {
				return nil, err
			}
			work, err := r.controlPolicy.ImageCacheWork(v.State, caller, q)
			if err != nil {
				return nil, err
			}
			return json.Marshal(work)
		}
		q, err := schema.Decode[control.ImageCacheRead](input)
		if err != nil {
			return nil, err
		}
		permit, err := r.controlPolicy.ImageCacheReadPermit(v.State, caller, time.Now().Unix(), q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "tunnel-reconnect-work" {
		if v.Local {
			return nil, mydcp.ErrAdmission
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
	if method == "compact-work" {
		if v.Local {
			return nil, mydcp.ErrAdmission
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
	if method == "task-restart-permit" {
		return r.taskRestartRead(key, input, v)
	}
	if method == "image-resolve-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.ImageResolveRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		result, err := r.resolveImageOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if method == "registry-prune-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		q, err := schema.Decode[registryPruneOwnerRequest](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		result, err := r.registryPruneOwner(ctx, q.Read, q.Results)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if method == "registry-catalog-owner" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.RegistryCatalogueRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		result, err := r.registryCatalogueOwner(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if method == "external-registry-probe" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		read, err := schema.Decode[control.ExternalRegistryProbeRead](input)
		if err != nil {
			return nil, mydcp.ErrAdmission
		}
		result, err := r.probeExternalRegistry(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if method == "ingress-observe" {
		return r.ingressReadModule(ctx, key, input)
	}
	if method == "container-read-permit" || method == "container-observe" {
		return r.containerReadModule(ctx, method, key, input, v)
	}
	if method == "node-storage-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
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
	if method == "node-storage-space-observe" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		root, err := schema.Decode[nodestorage.Root](input)
		if err != nil {
			return nil, err
		}
		owner, local := r.nativeOwner(root.Definition.Key)
		if !local {
			return nil, mydcp.ErrAdmission
		}
		value, err := owner.observeNodeStorageSpace(ctx, root)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	}
	if method == "volume-usage-observe" || method == "volume-backup-source-observe" || method == "volume-move-recipe-observe" || method == "volume-move-inputs-observe" {
		caller, err := identity.ParseKey(key)
		peer, known := r.Mesh.Peer(mydcp.Identity(caller))
		if err != nil || !known || !peer.Member {
			return nil, mydcp.ErrAdmission
		}
		if method == "volume-move-inputs-observe" {
			request, err := schema.Decode[control.VolumeMoveInputProbe](input)
			if err != nil {
				return nil, err
			}
			proof, err := r.observeVolumeMoveInputs(ctx, caller, request)
			if err != nil {
				return nil, err
			}
			return json.Marshal(proof)
		}
		ready, err := schema.Decode[volumes.NativeReady](input)
		if err != nil {
			return nil, err
		}
		owner, local := r.nativeOwner(ready.Owner.Key)
		if !local {
			return nil, mydcp.ErrAdmission
		}
		if method == "volume-move-recipe-observe" {
			value, err := owner.observeVolumeMoveRecipe(ctx, ready)
			if err != nil {
				return nil, err
			}
			return json.Marshal(value)
		}
		if method == "volume-backup-source-observe" {
			value, err := owner.observeVolumeBackupSource(ctx, ready)
			if err != nil {
				return nil, err
			}
			return json.Marshal(value)
		}
		value, err := owner.observeVolumeUsage(ctx, ready)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
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
	if method == "vault-approval-permit" || method == "vault-approval-result" {
		if v.Local {
			return nil, errors.New("managed quorum approval read required")
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		if method == "vault-approval-result" {
			command, err := state.DecodeCommand(input)
			if err != nil {
				return nil, err
			}
			result, err := r.controlPolicy.VaultApprovalResult(v.State, caller, command)
			if err != nil {
				return nil, err
			}
			return json.Marshal(result)
		}
		q, err := schema.Decode[control.VaultApprovalPermitRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At > now || now-q.At > 30 {
			return nil, errors.New("stale approval permit")
		}
		permit, err := r.controlPolicy.VaultApprovalPermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "vault-write-permit" {
		if v.Local {
			return nil, errors.New("managed quorum Vault read required")
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[control.VaultWritePermitRequest](input)
		if err != nil {
			return nil, err
		}
		now := time.Now().Unix()
		if q.At > now || now-q.At > 30 {
			return nil, errors.New("stale Vault permit request")
		}
		permit, err := r.controlPolicy.VaultWritePermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "checker-probe-permit" || method == "checker-shutdown-permit" || method == "app-native-permit" || method == "app-result" || method == "app-binding-permit" || method == "app-input-read-permit" {
		if v.Local {
			return nil, errors.New("managed quorum app read required")
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		if method == "checker-probe-permit" {
			if len(input) > control.MaxCheckerProbePermitBytes {
				return nil, mydcp.ErrAdmission
			}
			q, err := schema.Decode[control.CheckerProbeRequest](input)
			now := time.Now().UnixMilli()
			if err != nil || q.At > now || now-q.At > 30000 || q.DeadlineUnixMilli <= now {
				return nil, mydcp.ErrAdmission
			}
			permit, err := r.controlPolicy.CheckerProbePermit(v.State, caller, q)
			if err != nil {
				return nil, err
			}
			return json.Marshal(permit)
		}
		if method == "checker-shutdown-permit" {
			q, err := schema.Decode[control.CheckerShutdownRequest](input)
			now := time.Now().Unix()
			if err != nil || q.At > now || now-q.At > 30 {
				return nil, errors.New("stale shutdown check request")
			}
			permit, err := r.controlPolicy.CheckerShutdownPermit(v.State, caller, q)
			if err != nil {
				return nil, err
			}
			return json.Marshal(permit)
		}
		if method == "app-input-read-permit" {
			request, err := schema.Decode[control.AppInputFetch](input)
			now := time.Now().Unix()
			if err != nil || request.Binding.At > now || now-request.Binding.At > 30 {
				return nil, errors.New("stale input fetch request")
			}
			permit, err := r.controlPolicy.AppInputFetchPermit(v.State, caller, request)
			if err != nil {
				return nil, err
			}
			return json.Marshal(permit)
		}
		if method == "app-binding-permit" {
			request, err := schema.Decode[control.AppBindingRequest](input)
			now := time.Now().Unix()
			if err != nil || request.At > now || now-request.At > 30 {
				return nil, errors.New("stale app binding request")
			}
			permit, err := r.controlPolicy.AppBindingPermit(v.State, caller, request)
			if err != nil {
				return nil, err
			}
			return json.Marshal(permit)
		}
		if method == "app-native-permit" {
			request, err := schema.Decode[control.NativeRequest](input)
			if err != nil {
				return nil, err
			}
			permit, err := r.controlPolicy.NativePermit(v.State, caller, request)
			if err != nil {
				return nil, err
			}
			return json.Marshal(permit)
		}
		cmd, err := state.DecodeCommand(input)
		if err != nil {
			return nil, err
		}
		result, err := r.controlPolicy.AppResult(v.State, caller, cmd)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if method == "volume-create-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		scope, err := schema.Decode[volumes.Scope](input)
		if err != nil {
			return nil, err
		}
		work, err := r.controlPolicy.VolumeCreatePermit(v.State, caller, scope)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "volume-delete-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		scope, err := schema.Decode[volumes.Scope](input)
		if err != nil {
			return nil, err
		}
		work, err := r.controlPolicy.VolumeDeletePermit(v.State, caller, scope)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "volume-retained-delete-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		selection, err := schema.Decode[control.VolumeMoveSelection](input)
		if err != nil {
			return nil, err
		}
		work, err := r.controlPolicy.VolumeRetainedDeletePermit(v.State, caller, selection)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	if method == "volume-restore-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		request, err := schema.Decode[control.VolumeRestorePermitRequest](input)
		if err != nil {
			return nil, err
		}
		job, err := r.controlPolicy.VolumeRestorePermit(v.State, caller, request.Selection, request.Cleanup)
		if err != nil {
			return nil, err
		}
		return json.Marshal(job)
	}
	if method == "volume-backup-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		request, err := schema.Decode[control.VolumeBackupPermitRequest](input)
		if err != nil {
			return nil, err
		}
		job, err := r.controlPolicy.VolumeBackupPermit(v.State, caller, request.Selection, request.Cleanup)
		if err != nil {
			return nil, err
		}
		return json.Marshal(job)
	}
	if method == "volume-move-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		request, err := schema.Decode[control.VolumeMovePermitRequest](input)
		if err != nil {
			return nil, err
		}
		permit, err := r.controlPolicy.VolumeMovePermit(v.State, caller, request, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "volume-file-work" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		q, err := schema.Decode[volumeFileWorkRequest](input)
		now := time.Now().Unix()
		if err != nil || q.At > now || now-q.At > 30 {
			return nil, mydcp.ErrAdmission
		}
		job, err := r.controlPolicy.VolumeFileWork(v.State, caller, q.Session, q.ID, now)
		if err != nil {
			return nil, err
		}
		return json.Marshal(job)
	}
	if method == "volume-usage-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		ready, err := schema.Decode[volumes.NativeReady](input)
		if err != nil {
			return nil, err
		}
		index, err := r.controlPolicy.VolumeUsagePermit(v.State, caller, ready)
		if err != nil {
			return nil, err
		}
		return json.Marshal(index)
	}
	if method == "volume-permit" {
		if v.Local {
			return nil, errors.New("managed quorum volume read required")
		}
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		request, err := schema.Decode[volumes.StartRequest](input)
		if err != nil {
			return nil, err
		}
		policy := r.controlPolicy
		permit, err := policy.VolumePermit(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "plan" {
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
	if method != "observe" || len(input) != 0 {
		return nil, errors.New("invalid local observation")
	}

	return r.observeManaged(ctx, key, v)
}
