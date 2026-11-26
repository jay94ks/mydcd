// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network/services"
)

// RouteDispatchReport publishes only the original owner's durable dispatch
// identity. It is validated against the current reference instead of global
// Apps root equality. Epoch/replay floors remain unchanged.
// Dispatch remains unchanged across any envelope refresh or owner restart.
type RouteDispatchReport struct {
	Schema              uint8
	Kind                string
	Cluster, Reporter   [32]byte
	Epoch, RootRevision uint64
	Dispatch            services.RouteDispatch
	Signature           []byte
}

func RouteDispatchReportBytes(r RouteDispatchReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-route-dispatch-report-1\x00"), raw...)
}

func (r RouteDispatchReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: AppsKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.Target = state.RouteDispatchTarget
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func routeDispatchReportValue(raw []byte) bool {
	var head struct{ Kind string }
	return json.Unmarshal(raw, &head) == nil && head.Kind == "route-dispatch"
}

func (p Policy) routeDispatchReport(s state.State, cmd state.Command) (RouteDispatchReport, error) {
	var report RouteDispatchReport
	if cmd.Kind != state.ModuleReport || cmd.Key != AppsKey || canonical([]byte(cmd.Value), &report) != nil || report.Schema != 1 || report.Kind != "route-dispatch" || report.Cluster != p.Cluster || report.Reporter == ([32]byte{}) || report.Epoch != s.ModuleEpoch() || report.RootRevision != cmd.Expected || report.RootRevision == 0 || report.RootRevision > s.Object(AppsKey).Revision || !ed25519.Verify(ed25519.PublicKey(report.Reporter[:]), RouteDispatchReportBytes(report), report.Signature) {
		return report, ErrCatalog
	}
	original, err := report.Command()
	if err != nil || original != cmd {
		return report, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(report.Reporter) || !members.OwnsResource(report.Reporter, report.Dispatch.Reference.Owner) {
		return report, ErrCatalog
	}
	return report, nil
}

func (p Policy) reduceRouteDispatch(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	report, err := p.routeDispatchReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	work, err := p.RouteWork(s, report.Reporter, RouteWorkRequest{Reference: report.Dispatch.Reference.Consumer})
	if err != nil || work.Reference.Dispatch == nil && !work.PrepareAllowed {
		return nil, state.ConditionFailed
	}
	projection, err := p.ProjectResources(s)
	if err != nil || projection.NetworkAuthority == nil {
		return nil, state.Invalid
	}
	authority, err := projection.NetworkAuthority.RecordRouteDispatch(report.Dispatch)
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes, err := p.networkTransitionWrites(s, authority, projection.Resources.Networks, "", "", false)
	if err != nil {
		return nil, state.Invalid
	}
	return writes, state.Applied
}

type RouteNativeRequest struct {
	Reference, Nonce [32]byte
	Operation        uint64
	At               int64
}

// This permit covers the original first Apply only. It carries no Ready/Gone
// observation and never authorizes inventing a replacement journal or nonce.
type RouteNativePermit struct {
	Schema              uint8
	Reference           services.ReferenceNeed
	Journal, NativeSpec [32]byte
	Operation           uint64
}

func (p Policy) RouteNativePermit(s state.State, caller [32]byte, request RouteNativeRequest) (RouteNativePermit, error) {
	work, err := p.RouteWork(s, caller, RouteWorkRequest{Reference: request.Reference, At: request.At})
	if err != nil || !work.PrepareAllowed || work.Reference.Dispatch == nil || work.Tunnel.RoutePolicy == nil || work.Tunnel.RoutePolicy.Bridge == "" || request.Nonce == ([32]byte{}) || request.Operation != 1 {
		return RouteNativePermit{}, ErrCatalog
	}
	dispatch := work.Reference.Dispatch
	if dispatch.Operation != request.Operation || dispatch.Journal != services.RouteJournalDigest(work.Reference, request.Nonce) {
		return RouteNativePermit{}, ErrCatalog
	}
	return RouteNativePermit{Schema: 1, Reference: dispatch.Reference, Journal: dispatch.Journal, NativeSpec: dispatch.NativeSpec, Operation: dispatch.Operation}, nil
}
