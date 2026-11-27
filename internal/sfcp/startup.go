// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// A node opens its QUIC listener before its durable membership and
// handlers are loaded, because the consensus engine needs the bound
// address. Requests that peers send in that window are refused: the node
// cannot yet prove they are members (Observation reports a peer resends as
// soon as the link returns, management relays). The refusal is correct and
// the peers retry, so while the node is starting its admission refusals are
// counted, not logged one by one, and one summary line follows when the
// installation is proven (SetStarting(false)), when the transport closes,
// or after startingHold, whichever comes first. Any other failure is
// logged as usual.
type startupRefusals struct {
	mu     sync.Mutex
	on     bool
	timer  *time.Timer
	counts map[string]int
}

// startingHold bounds how long refusals are held: a node that waits longer
// (a join that cannot finish) logs them one by one again.
var startingHold = 60 * time.Second

// SetStarting marks this node as starting (true) or started (false). A
// transport starts out started; nothing about admission changes.
func (t *Transport) SetStarting(on bool) {
	var stop func()
	if on {
		stop = func() { t.SetStarting(false) }
	}
	if summary := t.starting.set(on, stop); summary != "" {
		log.Printf("SFCP refused peer requests while this node was starting (peers retry): %s", summary)
	}
}

func (r *startupRefusals) set(on bool, expire func()) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.on = on
	if on {
		r.timer = time.AfterFunc(startingHold, expire)
		return ""
	}
	if len(r.counts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.counts))
	for k, n := range r.counts {
		parts = append(parts, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(parts)
	r.counts = nil
	return strings.Join(parts, " ")
}

// hold counts one admission refusal while starting and reports whether it
// did.
func (r *startupRefusals) hold(stage, cause string) bool {
	if cause != "admission" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.on {
		return false
	}
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.counts["stage="+stage]++
	return true
}
