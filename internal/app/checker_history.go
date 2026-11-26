// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func validCheckerRecent(rows []containerops.DetailCheck) bool {
	if len(rows) > 20 {
		return false
	}
	for i, row := range rows {
		if row.Checker == "" || len(row.Checker) > 128 || row.Phase != "startup" && row.Phase != "readiness" && row.Phase != "liveness" && row.Phase != "shutdown" || row.Status != "pass" && row.Status != "fail" && row.Status != "unknown" || row.At.IsZero() || row.DurationMS < 0 || row.ConsecutiveFailures == nil || row.Generation == 0 || row.Revision < row.Generation || len(row.RunID) != 64 || row.NativeID == "" || row.Message != "check passed" && row.Message != "check failed" && row.Message != "check result unavailable" {
			return false
		}
		for _, old := range rows[:i] {
			if old.RunID == row.RunID {
				return false
			}
		}
	}
	return true
}

// The existing observation row owns its recent public summaries. A new run
// does not reset them, and repeated durable control/receipt saves do not append
// a duplicate. No script output/parameters/probe bytes become display messages.
func (r *Runtime) retainCheckerRecent(p *checkerObservation, key string) error {
	if r.reports == nil {
		return checker.ErrContract
	}
	oldRaw, err := r.reports.GetBounded(key, maxCheckerObservationBytes)
	if err == nil {
		old, decodeErr := schema.Decode[checkerObservation](oldRaw)
		if decodeErr != nil || old.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
			return checker.ErrContract
		}
		if old.Task.Key == p.Task.Key {
			p.Recent = slices.Clone(old.Recent)
		} else {
			p.Recent = nil
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	last := p.Checkpoint.Last
	if last == nil || slices.ContainsFunc(p.Recent, func(row containerops.DetailCheck) bool { return row.RunID == last.Run.Request.RunID }) {
		return nil
	}
	var native string
	for _, target := range last.Run.Request.Targets {
		if target.TaskKey == p.Task.Key {
			native = target.NativeID
			break
		}
	}
	message := "check result unavailable"
	if last.Result.Status == "pass" {
		message = "check passed"
	} else if last.Result.Status == "fail" {
		message = "check failed"
	}
	failures := p.Checkpoint.Failures
	row := containerops.DetailCheck{Checker: last.Run.Request.Checker, Phase: string(last.Run.Request.Phase), Status: string(last.Result.Status), At: time.UnixMilli(last.At).UTC(), DurationMS: max(0, last.At-last.Run.PreparedAt), Message: message, ConsecutiveFailures: &failures, RunID: last.Run.Request.RunID, NativeID: native, Generation: p.Task.Generation, Revision: p.Task.Revision}
	p.Recent = append(p.Recent, row)
	if len(p.Recent) > 20 {
		p.Recent = slices.Clone(p.Recent[len(p.Recent)-20:])
	}
	if !validCheckerRecent(p.Recent) {
		return checker.ErrContract
	}
	return nil
}

func (r *Runtime) addContainerCheckerDetails(result *containerops.Result, q containerops.Query) error {
	if result == nil || result.Detail == nil || q.Kind != "inspect" {
		return containerops.ErrQuery
	}
	if r.reports == nil {
		return checker.ErrContract
	}
	// Read durable rows directly. A slow in-flight checker need not finish
	// before a read-only inspector can show its last completed observations.
	prefix := checkerObservationPrefix + result.Target.Tenant + "/" + result.Target.App + "/service/" + result.Target.Service + "/"
	index, err := r.reports.SizesBounded(prefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return err
	}
	limit := q.HistoryLimit
	if limit == 0 {
		limit = 20
	}
	for key := range index {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		raw, err := r.reports.GetBounded(key, maxCheckerObservationBytes)
		if err != nil {
			return err
		}
		point, err := schema.Decode[checkerObservation](raw)
		if err != nil || point.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || checkerObservationKey(point.Checkpoint.Definition) != key || point.Checkpoint.Definition.Request.Tenant != result.Target.Tenant || point.Checkpoint.Definition.Request.App != result.Target.App {
			return checker.ErrContract
		}
		if point.Task.Key != result.Target.Instance || point.Checkpoint.Definition.Scope != result.Target.Service {
			continue
		}
		rows := point.Recent[max(0, len(point.Recent)-limit):]
		result.Detail.Checks = append(result.Detail.Checks, rows...)
	}
	slices.SortFunc(result.Detail.Checks, func(a, b containerops.DetailCheck) int {
		if d := b.At.Compare(a.At); d != 0 {
			return d
		}
		return strings.Compare(a.Checker, b.Checker)
	})
	if len(result.Detail.Checks) > 100 {
		result.Detail.Checks = result.Detail.Checks[:100]
		result.Detail.ChecksTruncated = true
	}
	raw, err := json.Marshal(result.Detail)
	if err != nil || len(raw) > containerops.MaxDetailWindowBytes {
		return containerops.ErrLimit
	}
	return result.ValidateDetailWindow(q, result.Target)
}
