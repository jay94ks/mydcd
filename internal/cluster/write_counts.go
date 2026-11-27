// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// WriteCount is how many Raft log entries one kind of write appended through
// this node since it last became leader. It is leader memory, never Raft
// state: R14 uses it to find what an idle cluster still writes.
type WriteCount struct {
	Kind  string
	Count uint64
}

// Write counts are bounded: a label is a fixed command kind, a state key and
// a short symbolic action (no tenant, app or node names), and at most writeKindLimit labels are kept.
const writeKindLimit = 128

type writeCounts struct {
	mu     sync.Mutex
	term   uint64
	since  time.Time
	counts map[string]uint64
}

var commandKindNames = map[state.CommandKind]string{
	state.Mutate: "mutate", state.SetRights: "set-rights", state.RotateLedger: "rotate-ledger",
	state.Module: "change", state.ModuleWindow: "window", state.ModuleReport: "report",
	state.ModuleUpload: "upload", state.ModuleAppCAS: "app-down",
}

// writeLabel names a command without its contents: kind, key and, for module
// commands, the symbolic action or report kind it carries.
func writeLabel(c state.Command) string {
	kind, ok := commandKindNames[c.Kind]
	if !ok {
		kind = "unknown"
	}
	label := kind + " " + keyClass(c.Key)
	var peek struct {
		Action, Kind string
		Change       struct{ Action string }
	}
	if c.Kind != state.Mutate && json.Unmarshal([]byte(c.Value), &peek) == nil {
		for _, a := range []string{peek.Change.Action, peek.Action, peek.Kind} {
			if symbolicAction(a) {
				label += " " + a
				break
			}
		}
	}
	return label
}

// keyClass keeps only the fixed namespace of a state key. Deeper segments
// name tenants, apps, nodes or networks, which a write count must not carry.
func keyClass(key string) string {
	parts := strings.SplitN(key, "/", 3)
	n := 1
	if parts[0] == "control" && len(parts) > 1 {
		n = 2
	}
	if len(parts) > n {
		return strings.Join(parts[:n], "/") + "/…"
	}
	return key
}

func symbolicAction(a string) bool {
	if a == "" || len(a) > 48 {
		return false
	}
	return strings.Trim(a, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

// add counts one appended entry under label for the given leader term. A new
// term starts the counts again, so they always describe one leadership.
func (w *writeCounts) add(term uint64, label string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.term != term || w.counts == nil {
		w.term, w.since, w.counts = term, time.Now(), map[string]uint64{}
	}
	if _, ok := w.counts[label]; !ok && len(w.counts) >= writeKindLimit {
		label = "other"
	}
	w.counts[label]++
}

// WriteCounts returns this node's counts for its current leader term, most
// frequent first, and when they started. Zero time means nothing counted yet.
func (e *Engine) WriteCounts() ([]WriteCount, time.Time) {
	w := &e.writes
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.term != e.raft.CurrentTerm() || !e.IsLeader() {
		return nil, time.Time{}
	}
	out := make([]WriteCount, 0, len(w.counts))
	for k, n := range w.counts {
		out = append(out, WriteCount{Kind: k, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Kind < out[j].Kind
	})
	return out, w.since
}
