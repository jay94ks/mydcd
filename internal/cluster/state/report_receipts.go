// SPDX-License-Identifier: Apache-2.0

package state

import (
	"encoding/hex"
	"sort"
	"strings"
)

const maxReportRoots = 16

type reportRoot struct{ Actor, Key string }
type reportReceipt struct {
	Key      string
	Expected uint64
}
type reportReceiptRow struct {
	Actor, ID, Key string
	Expected       uint64
}
type reportFloorRow struct {
	Actor, Key string
	Before     uint64
}

func (s State) reportRootAvailable(actor, key string) bool {
	roots := map[string]bool{}
	for k := range s.reportFloors {
		if k.Actor == actor {
			roots[k.Key] = true
		}
	}
	s.actorReports(actor, func(_ requestKey, r reportReceipt) bool {
		roots[r.Key] = true
		return true
	})
	return roots[key] || len(roots) < maxReportRoots
}

func reportRows(s State) ([]reportReceiptRow, []reportFloorRow) {
	var reports []reportReceiptRow
	var floors []reportFloorRow
	s.reportReceipts.walk("", func(k string, v reportReceipt) bool {
		key, _ := parseRequestKey(k)
		reports = append(reports, reportReceiptRow{key.actor, key.id, v.Key, v.Expected})
		return true
	})
	for k, v := range s.reportFloors {
		floors = append(floors, reportFloorRow{k.Actor, k.Key, v})
	}
	sort.Slice(reports, func(i, j int) bool {
		a, b := reports[i], reports[j]
		return a.Actor < b.Actor || a.Actor == b.Actor && a.ID < b.ID
	})
	sort.Slice(floors, func(i, j int) bool {
		a, b := floors[i], floors[j]
		return a.Actor < b.Actor || a.Actor == b.Actor && a.Key < b.Key
	})
	return reports, floors
}

func restoreReportRows(s *State, reports []reportReceiptRow, floors []reportFloorRow) error {
	s.reportReceipts = tree[reportReceipt]{}
	s.reportFloors = map[reportRoot]uint64{}
	for _, row := range floors {
		key := reportRoot{row.Actor, row.Key}
		if _, exists := s.reportFloors[key]; exists {
			return ErrSnapshot
		}
		if _, known := s.principals[row.Actor]; !known || !strings.HasPrefix(row.Actor, "node/") || !strings.HasPrefix(row.Key, "control/") || len(row.Key) <= len("control/") || len(row.Key) > 512 || row.Before == 0 || row.Before > s.Object(row.Key).Revision || !s.reportRootAvailable(row.Actor, row.Key) {
			return ErrSnapshot
		}
		s.reportFloors[key] = row.Before
	}
	for _, row := range reports {
		key := requestKey{row.Actor, row.ID}
		stored, known := s.request(key)
		if _, exists := s.reportReceipts.get(key.String()); exists {
			return ErrSnapshot
		}
		if !known || !strings.HasPrefix(row.Actor, "node/") || !strings.HasPrefix(row.ID, "checkpoint/") || len(row.ID) != len("checkpoint/")+64 || !strings.HasPrefix(row.Key, "control/") || len(row.Key) <= len("control/") || len(row.Key) > 512 || row.Expected >= stored.result.Index || !s.reportRootAvailable(row.Actor, row.Key) {
			return ErrSnapshot
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(row.ID, "checkpoint/")); err != nil {
			return ErrSnapshot
		}
		s.putReport(key, reportReceipt{row.Key, row.Expected})
	}
	return nil
}

// ReportRequestID binds the FULL command including its signed module payload.
// A reclaimed ID cannot be reused with a later CAS or different contents.
func ReportRequestID(c Command) string {
	c.RequestID = ""
	d := Digest(c)
	return "checkpoint/" + hex.EncodeToString(d[:])
}

func validReport(c Command, index uint64) bool {
	return c.Kind == ModuleReport && strings.HasPrefix(c.Actor, "node/") && strings.HasPrefix(c.Key, "control/") && len(c.Key) > len("control/") && !c.Delete && (c.Target == "" || scopedAppReport(c)) && c.Rights == 0 && c.Expected <= index && c.RequestID == ReportRequestID(c)
}

func (s State) reportExpired(c Command) bool {
	if c.Kind != ModuleReport || c.Expected >= s.reportFloors[reportRoot{c.Actor, c.Key}] {
		return false
	}
	// Keep the exact latest original result, including a lost final ACK, even
	// when its CAS is behind the namespace replay fence.
	if r, ok := s.request(requestKey{c.Actor, c.RequestID}); ok && r.digest == Digest(c) {
		return false
	}
	return true
}

// collectReports mutates only an unpublished candidate whose typed report has
// ALREADY passed authorization, CAS, reducer and complete policy validation.
// Failed collection rolls back the entire candidate at the caller.
func collectReports(s *State, actor string) bool {
	roots := map[string]uint64{}
	latest := map[string]uint64{}
	for key, floor := range s.reportFloors {
		if key.Actor == actor {
			roots[key.Key] = floor
		}
	}
	missing := false
	type entry struct {
		key requestKey
		m   reportReceipt
	}
	var entries []entry
	s.actorReports(actor, func(key requestKey, m reportReceipt) bool {
		r, exists := s.request(key)
		if !exists {
			missing = true
			return false
		}
		entries = append(entries, entry{key, m})
		roots[m.Key] = max(roots[m.Key], s.Object(m.Key).Revision)
		latest[m.Key] = max(latest[m.Key], r.result.Index)
		return true
	})
	if missing || len(roots) > maxReportRoots {
		return false
	}
	for _, e := range entries {
		r, _ := s.request(e.key)
		// A superseded CAS is stale, and a rejected result changed nothing, so
		// its replay only re-runs the reducer on current state. Either may go,
		// but the newest receipt per root stays for a lost final ACK.
		if (e.m.Expected < roots[e.m.Key] || r.result.Code != Applied) && r.result.Index != latest[e.m.Key] {
			s.dropReport(e.key)
			s.dropRequest(e.key)
		}
	}
	if s.reportFloors == nil {
		s.reportFloors = map[reportRoot]uint64{}
	}
	for key, floor := range roots {
		if floor != 0 {
			s.reportFloors[reportRoot{actor, key}] = floor
		}
	}
	return s.requestCount(actor) < LedgerLimit
}

// ReportLedgerFull says whether actor's request ledger is at its limit or
// has no room for another report root, so a new report from it can only be
// applied if it succeeds and frees older receipts. Local diagnostics only.
func (s State) ReportLedgerFull(actor, key string) bool {
	return s.requestCount(actor) >= LedgerLimit || !s.reportRootAvailable(actor, key)
}
