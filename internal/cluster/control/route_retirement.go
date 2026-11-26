// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// RouteRetirementReport joins the exact original instance and policy closure.
// It only settles an already revoking policy and cannot grant new authority.
type RouteRetirementReport struct {
	Schema                                 uint8
	Kind                                   string
	Cluster, Reporter                      [32]byte
	Epoch, RootRevision, ResourcesRevision uint64
	Dispatch                               services.RouteDispatch
	Close                                  services.ReferenceClose
	Route                                  tenancy.RouteClosure
	NeverDispatched                        bool `json:",omitempty"`
	Signature                              []byte
}

func RouteRetirementReportBytes(r RouteRetirementReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-route-retirement-report-1\x00"), raw...)
}

func (r RouteRetirementReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	command := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: AppsKey, Expected: r.RootRevision, Value: string(raw)}
	command.RequestID = state.ReportRequestID(command)
	_, err = state.EncodeCommand(command)
	return command, err
}

func routeRetirementReportValue(raw []byte) bool {
	var head struct{ Kind string }
	return json.Unmarshal(raw, &head) == nil && head.Kind == "route-retirement"
}

func (p Policy) routeRetirementReport(s state.State, command state.Command) (RouteRetirementReport, error) {
	var report RouteRetirementReport
	if command.Kind != state.ModuleReport || command.Key != AppsKey || canonical([]byte(command.Value), &report) != nil || report.Schema != 1 || report.Kind != "route-retirement" || report.Cluster != p.Cluster || report.Reporter == ([32]byte{}) || report.Close.Owner != report.Route.Owner || report.Epoch != s.ModuleEpoch() || report.RootRevision != command.Expected || !ed25519.Verify(ed25519.PublicKey(report.Reporter[:]), RouteRetirementReportBytes(report), report.Signature) {
		return report, ErrCatalog
	}
	if report.NeverDispatched {
		zero, _ := json.Marshal(services.RouteDispatch{})
		received, _ := json.Marshal(report.Dispatch)
		if !bytes.Equal(zero, received) {
			return report, ErrCatalog
		}
	} else if report.Dispatch.Reference.Owner != report.Close.Owner || report.Dispatch.Reference.Consumer != report.Close.Consumer {
		return report, ErrCatalog
	}
	original, err := report.Command()
	if err != nil || original != command {
		return report, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(report.Reporter) || !members.OwnsResource(report.Reporter, report.Close.Owner) {
		return report, ErrCatalog
	}
	return report, nil
}

func (p Policy) reduceRouteRetirement(s state.State, command state.Command) (map[string][]byte, state.Code) {
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	report, err := p.routeRetirementReport(s, command)
	if err != nil {
		return nil, state.Forbidden
	}
	if report.ResourcesRevision != s.Object(ResourcesKey).Revision {
		return nil, state.ConditionFailed
	}
	projection, err := p.ProjectResources(s)
	if err != nil || projection.NetworkAuthority == nil {
		return nil, state.Invalid
	}
	ref, exists := projection.NetworkAuthority.ReferenceConsumer(report.Close.Consumer)
	if !exists || ref.Route == nil || ref.Native == nil || !p.ownsResource(s, report.Reporter, ref.Local.Owner) || report.Close.Native != ref.RouteNativeKey() || report.NeverDispatched != (ref.Dispatch == nil) {
		return nil, state.ConditionFailed
	}
	if !report.NeverDispatched {
		original, _ := json.Marshal(ref.Dispatch)
		received, _ := json.Marshal(report.Dispatch)
		if !bytes.Equal(original, received) {
			return nil, state.ConditionFailed
		}
	}
	authority, networks, err := projection.NetworkAuthority.ObserveRouteRetired(projection.Resources.Networks, report.Close, report.Route, report.Close.At)
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes, err := p.networkTransitionWrites(s, authority, networks, "", "", false)
	if err != nil {
		return nil, state.Invalid
	}
	if networks.Revision() != projection.Resources.Networks.Revision() {
		// Projection includes app-owned networks and Task reservations. It is
		// a validation view, never a replacement for the management catalog.
		resources, err := p.Resources(s)
		if err != nil {
			return nil, state.Invalid
		}
		resources.Networks, err = resources.Networks.ObserveRetired(report.Route)
		if err != nil {
			return nil, state.ConditionFailed
		}
		resourceWrites, code := p.resourceCheckpoint(s, resources)
		if code != state.Applied {
			return nil, code
		}
		for key, raw := range resourceWrites {
			writes[key] = raw
		}
	}
	return writes, state.Applied
}
