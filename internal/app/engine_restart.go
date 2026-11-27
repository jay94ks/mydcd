// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"strings"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/moby/moby/api/types/events"
)

// restartEvents is the engine event handler for restarts (R18 E5): every
// container runs with restart policy "no", so a container of this node that
// stops (die, OOM kill) wakes a reconciliation pass at once, and that pass
// decides whether to start it again (Task, standalone and cluster app rules
// stay where they are). A new engine boot or a gap wakes one pass too, which
// finds containers that stopped while no events arrived.
func (r *Runtime) restartEvents() engineevents.Handler {
	return engineevents.Handler{
		Name:  "restart",
		Wants: r.ownStoppedContainer,
		Handle: func(context.Context, engineevents.Record) error {
			r.wakeModules()
			return nil
		},
		Rescan: func(context.Context) error {
			r.wakeModules()
			return nil
		},
	}
}

func (r *Runtime) ownStoppedContainer(m events.Message) bool {
	if m.Type != events.ContainerEventType || r.owner == "" || m.Actor.Attributes["org.sfc.owner"] != r.owner {
		return false
	}
	switch m.Action {
	case events.ActionDie, events.ActionOOM:
		return true
	case "seafield.memory":
		return strings.Contains(","+m.Actor.Attributes["changed"]+",", ",oom_kill,")
	}
	return false
}
