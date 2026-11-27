// SPDX-License-Identifier: Apache-2.0

package app

import (
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
)

func (r *Runtime) addContainerEventHistory(result *containerops.Result, q containerops.Query) error {
	if result == nil || result.Detail == nil || q.Kind != "inspect" {
		return nil
	}
	r.mu.RLock()
	collectFailed := r.eventError != nil
	r.mu.RUnlock()
	if r.events == nil {
		result.Detail.HistoryIncomplete = true
		return nil
	}
	limit := q.HistoryLimit
	if limit == 0 {
		limit = 20
	}
	rows, incomplete, err := r.events.History(result.Target.Tenant, result.Target.App, result.Target.Instance, limit, uint64(time.Now().UnixMilli()))
	result.Detail.HistoryIncomplete = incomplete || err != nil || collectFailed
	if err != nil {
		return nil
	}
	result.Detail.History = nil
	for _, row := range rows {
		e := row.Event
		result.Detail.History = append(result.Detail.History, containerops.DetailHistory{ID: row.ID, Kind: e.Kind, Reason: e.Detail.Reason, NativeID: e.Target.Native, At: time.UnixMilli(int64(e.At)).UTC(), ExitCode: e.Detail.ExitCode, Generation: e.Target.Generation, Revision: e.Target.Revision})
	}
	return nil
}
