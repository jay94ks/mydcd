// SPDX-License-Identifier: Apache-2.0

package app

import "github.com/jay94ks/seafield/internal/engineevents"

// engineEventHandlers lists every feature that reads the engine's event feed
// (purpose 32): restart decisions, network leases, the event bus, log fetch,
// memory and pressure measurements. A feature adds one engineevents.Handler
// value written in its own files; the consumer owns the cursor, gaps and
// engine reboots. See devel/refactor/18-sfcd-structure.md 5.3.
func (r *Runtime) engineEventHandlers() []engineevents.Handler {
	bus := newEngineBus(r.bus.Publish, func() string {
		if e := r.Engine(); e != nil {
			return e.ObservedNodeID()
		}
		return ""
	})
	return []engineevents.Handler{r.restartEvents(), r.diagnosticEvents(), r.engineLogHandler(), bus.handler()}
}
