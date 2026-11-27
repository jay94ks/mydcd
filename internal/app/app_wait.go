// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

// noteAppWait logs why this owner leaves an app step unprepared or unsent.
// A step logs again only when its reason changes; "" clears it once the step
// moves. The text names keys, nodes and checks only, never secret values.
func (r *Runtime) noteAppWait(app control.AppView, revision uint64, key, reason string) {
	id := fmt.Sprintf("%s/%s/%s", app.Tenant, app.App, key)
	r.appWaitMu.Lock()
	defer r.appWaitMu.Unlock()
	old, seen := r.appWaits[id]
	if reason == "" {
		if seen {
			delete(r.appWaits, id)
			log.Printf("app step %s (op %s, rev %d): moving", id, app.Operation.ID, revision)
		}
		return
	}
	if seen && old == reason {
		return
	}
	if r.appWaits == nil {
		r.appWaits = map[string]string{}
	}
	if len(r.appWaits) >= 4096 {
		clear(r.appWaits)
	}
	r.appWaits[id] = reason
	log.Printf("app step %s (op %s, rev %d) waiting: %s", id, app.Operation.ID, revision, reason)
}

func (r *Runtime) appDependencyWait(e deployment.Execution, key string) string {
	pending := e.WaitingOn(key, uint64(time.Now().Unix()))
	if len(pending) == 0 {
		return ""
	}
	return "; waiting on " + strings.Join(pending, ", ")
}
