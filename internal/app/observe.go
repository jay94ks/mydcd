// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"maps"
	"slices"
	"strings"
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
