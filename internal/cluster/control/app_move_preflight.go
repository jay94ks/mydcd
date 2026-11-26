// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/observability"
)

// MoveStoragePreflight is a public measurement, never a reservation, native
// readiness witness or permission to quiesce the original writer.
type MoveStoragePreflight struct {
	Node              string
	State             string // unknown, stale, available, insufficient
	RequiredBytes     uint64
	AvailableBytes    *uint64 `json:",omitempty"`
	ObservedAt        uint64  // Unix milliseconds, like the original node report
	ObservationMaxAge uint64
	MeasurementOnly   bool
}

func (v MoveStoragePreflight) valid() bool {
	if !validID(v.Node) || v.RequiredBytes == 0 || v.ObservationMaxAge != observability.MaxAge || !v.MeasurementOnly {
		return false
	}
	if v.State == "unknown" {
		return v.AvailableBytes == nil && v.ObservedAt == 0
	}
	if v.AvailableBytes == nil || v.ObservedAt == 0 {
		return false
	}
	return v.State == "stale" || v.State == "available" && *v.AvailableBytes >= v.RequiredBytes || v.State == "insufficient" && *v.AvailableBytes < v.RequiredBytes
}

// nowMillis has the same precision as Report.At; session authorization still
// consumes Unix seconds. Rounding now down before comparing reports would
// incorrectly discard observations made within the current second.
func (p Policy) VolumeMoveStoragePreflight(s state.State, session access.Session, nowMillis uint64, tenant, node string, required uint64, reports []observability.Report) (MoveStoragePreflight, error) {
	var zero MoveStoragePreflight
	if tenant == "" || node == "" || required == 0 || nowMillis == 0 {
		return zero, access.ErrInvalid
	}
	at := int64(nowMillis / 1000)
	a, err := p.observationAccess(s, session, at, tenant, node, true)
	if err != nil {
		return zero, err
	}
	if a.catalog.AuthorizeSession(session, a.policy.Cluster, a.policy.Issuer(session.Issuer), at, tenant, access.Deploy, node) != nil {
		return zero, access.ErrDenied
	}
	v := MoveStoragePreflight{Node: node, State: "unknown", RequiredBytes: required, ObservationMaxAge: observability.MaxAge, MeasurementOnly: true}
	report, known := allowedNodeReports(a, reports)[node]["disk/container-runtime"]
	if !known || report.Disk == nil || report.Index > s.Index() || report.At > nowMillis {
		return v, nil
	}
	available := report.Disk.Available
	v.AvailableBytes, v.ObservedAt = &available, report.At
	switch {
	case !observability.Fresh(report.At, nowMillis):
		v.State = "stale"
	case available < required:
		v.State = "insufficient"
	default:
		v.State = "available"
	}
	return v, nil
}
