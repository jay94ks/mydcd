// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/moby/moby/api/types/events"
)

const dockerOwnerPrefix = "diagnostic-source/docker-owner/"

type dockerEventOwner struct {
	Schema                                      uint8
	Cluster, Owner                              [32]byte
	Target                                      eventlog.Target
	Name, Spec                                  string
	Boot                                        string `json:",omitempty"`
	EverStarted                                 bool
	LastStart, RestartedStart, LastDie, LastOOM int64
}

func dockerOwnerKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return dockerOwnerPrefix + hex.EncodeToString(sum[:])
}

func (r *Runtime) ownedDockerEvent(ctx context.Context, message events.Message) (dockerEventOwner, error) {
	var out dockerEventOwner
	labels := message.Actor.Attributes
	key := labels["org.sfc.key"]
	parts := strings.Split(key, "/")
	if r.workload == nil || r.docker == nil || len(parts) != 5 || parts[0] != "workload" || parts[1] != "task" || labels["org.sfc.owner"] != r.docker.Owner || labels["org.sfc.kind"] != "container" || message.Actor.ID == "" || len(message.Actor.ID) > 256 {
		return out, sfcEventForeign
	}
	if raw, err := r.reports.GetBounded(dockerOwnerKey(message.Actor.ID), 4096); err == nil {
		out, err = schema.Decode[dockerEventOwner](raw)
		if err != nil || out.Schema != 1 || !out.Target.Valid() || out.Cluster != r.controlPolicy.Cluster || out.Owner != r.Identity.Public || out.Target.Task != key || out.Target.Native != message.Actor.ID || out.Name != strings.TrimPrefix(labels["name"], "/") || out.Spec != labels["org.sfc.spec"] || strconv.FormatUint(out.Target.Generation, 10) != labels["org.sfc.generation"] {
			return dockerEventOwner{}, eventlog.ErrInvalid
		}
		return out, nil
	} else if !errors.Is(err, storage.ErrMissing) {
		return out, err
	}
	record, err := r.workload.View(key)
	if err != nil {
		return out, sfcEventForeign
	}
	candidates := []reconcile.Resource{record.State.Applied, record.State.Desired.Resource}
	if record.State.Pending != nil {
		candidates = append(candidates, record.State.Pending.Target)
	}
	var generation uint64
	for _, resource := range candidates {
		if !resource.Present {
			continue
		}
		id, err := r.docker.Identity("container", key, workload.TaskIdentityResource(resource))
		if err == nil && id.Matches(labels["name"], labels) {
			generation = resource.Generation
			out.Name = id.Name
			out.Spec = labels["org.sfc.spec"]
			break
		}
	}
	if generation == 0 {
		return out, sfcEventForeign
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return out, err
	}
	out.Target, err = r.controlPolicy.DiagnosticTask(view.State, key, generation, r.Identity.Public, message.Actor.ID)
	if err != nil {
		return out, sfcEventForeign
	}
	out.Schema = 1
	out.Cluster = r.controlPolicy.Cluster
	out.Owner = r.Identity.Public
	if !out.Target.Valid() {
		return dockerEventOwner{}, eventlog.ErrInvalid
	}
	if index, err := r.reports.SizesBounded(dockerOwnerPrefix, 16384, 2<<20); err != nil || len(index) >= 16384 {
		return out, errDockerEventOwnerBudget
	}
	return out, nil
}

var sfcEventForeign = errors.New("event is outside a retained task identity")
var errDockerEventOwnerBudget = errors.New("diagnostic native owner budget reached")

// diagnosticEvents is the engine event handler that records a container's
// starts, exits, restarts and probe results in the event log (R18 E5). The
// engine feed's own cursor orders and deduplicates records, so this keeps
// no position of its own; a gap or a new engine boot is recorded as a
// collection gap, because events in between may be lost.
func (r *Runtime) diagnosticEvents() engineevents.Handler {
	boot, bootAt := diagnosticBoot()
	return engineevents.Handler{
		Name:  "diagnostic",
		Wants: r.diagnosticContainerEvent,
		Handle: func(ctx context.Context, rec engineevents.Record) error {
			return r.applyDockerEvent(ctx, rec.Event, boot, bootAt)
		},
		Rescan: func(context.Context) error {
			if r.workload == nil || r.docker == nil || r.events == nil {
				return nil
			}
			now := uint64(time.Now().UnixMilli())
			_, err := r.events.Append(fmt.Sprintf("engine-event-gap/%d", time.Now().UnixNano()), eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: r.Engine().ObservedNodeID()}, Detail: eventlog.Detail{Code: "ENGINE_EVENTS_MISSED"}}, now)
			return err
		},
	}
}

func (r *Runtime) diagnosticContainerEvent(m events.Message) bool {
	if m.Type != events.ContainerEventType || r.owner == "" || m.Actor.Attributes["org.sfc.owner"] != r.owner || m.Actor.Attributes["org.sfc.kind"] != "container" {
		return false
	}
	switch m.Action {
	case "create", "start", "restart", "oom", "die", "destroy":
		return true
	}
	return strings.HasPrefix(string(m.Action), "health_status")
}

func (r *Runtime) applyDockerEvent(ctx context.Context, message events.Message, boot string, bootAt int64) error {
	if string(message.Type) != "container" || r.workload == nil || r.docker == nil || r.events == nil {
		return nil
	}
	nano := message.TimeNano
	if nano <= 0 && message.Time > 0 && message.Time <= int64(^uint64(0)>>1)/int64(time.Second) {
		nano = message.Time * int64(time.Second)
	}
	if nano <= 0 {
		return eventlog.ErrInvalid
	}
	now := uint64(time.Now().UnixMilli())
	owner, err := r.ownedDockerEvent(ctx, message)
	if errors.Is(err, sfcEventForeign) || errors.Is(err, errDockerEventOwnerBudget) {
		code := "NATIVE_EVENT_IDENTITY_UNAVAILABLE"
		if errors.Is(err, errDockerEventOwnerBudget) {
			code = "NATIVE_EVENT_OWNER_BUDGET"
		}
		// A container already retired before history could be reconstructed is
		// not invented as another task. Surface an explicit collection gap.
		_, err = r.events.Append(fmt.Sprintf("docker-identity-gap/%s/%d", message.Actor.ID, nano), eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: r.Engine().ObservedNodeID()}, Detail: eventlog.Detail{Code: code}}, now)
		return err
	} else if err != nil {
		return err
	}
	updates := map[string][]byte{}
	action := string(message.Action)
	owner, kind, detail := dockerEventTransition(owner, message, nano, boot, bootAt)
	if action == "destroy" {
		updates[dockerOwnerKey(message.Actor.ID)] = nil
	} else {
		raw, _ := json.Marshal(owner)
		updates[dockerOwnerKey(message.Actor.ID)] = raw
	}
	if kind == "" {
		return r.events.UpdateRelated(updates, now)
	}
	t := owner.Target
	if (kind == "task-exited" || kind == "task-restarted") && detail.Reason != "oom" && detail.Reason != "node-restart" {
		r.dockerEventActionReason(ctx, t, &detail, nano)
	}
	event := eventlog.Event{Kind: kind, Scope: "app", At: uint64(nano / int64(time.Millisecond)), Target: t, Detail: detail}
	if event.At <= now && now-event.At > eventlog.RetentionMillis {
		event = eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: r.Engine().ObservedNodeID()}, Detail: eventlog.Detail{Code: "DOCKER_EVENT_EXPIRED"}}
	}
	tag := fmt.Sprintf("docker/%s/%s/%d", t.Native, action, nano)
	_, err = r.events.AppendRelated(tag, event, now, updates)
	return err
}

// dockerEventTransition is the shared diagnostic transition for authenticated
// native events. It does not control a container or manufacture Task identity.
func dockerEventTransition(owner dockerEventOwner, message events.Message, nano int64, boot string, bootAt int64) (dockerEventOwner, string, eventlog.Detail) {
	action := string(message.Action)
	detail := eventlog.Detail{}
	kind := ""
	switch action {
	case "start":
		if nano > owner.LastStart {
			if owner.EverStarted || owner.LastDie > 0 {
				kind = "task-restarted"
				detail.Reason = "restart"
				if owner.Boot != "" && boot != "" && owner.Boot != boot && bootAt > 0 && nano >= bootAt {
					detail.Reason = "node-restart"
				}
				owner.RestartedStart = nano
			}
			owner.EverStarted = true
			owner.LastStart = nano
			if bootAt > 0 && nano >= bootAt {
				owner.Boot = boot
			}
		}
	case "restart":
		if owner.RestartedStart == 0 || owner.RestartedStart != owner.LastStart {
			kind = "task-restarted"
			detail.Reason = "user"
			owner.RestartedStart = owner.LastStart
			if owner.RestartedStart == 0 {
				owner.RestartedStart = nano
			}
		}
	case "oom":
		owner.LastOOM = max(owner.LastOOM, nano)
	case "die":
		if nano > owner.LastDie {
			kind = "task-exited"
			detail.Reason = "exit"
			if owner.LastOOM >= owner.LastStart && owner.LastOOM > 0 {
				detail.Reason = "oom"
			}
			owner.LastDie = nano
			if value, e := strconv.Atoi(message.Actor.Attributes["exitCode"]); e == nil {
				detail.ExitCode = &value
			} else {
				detail.Code = "EXIT_CODE_UNAVAILABLE"
			}
		}
	case "health_status: unhealthy":
		kind = "probe-failed"
		detail.Checker = "docker-health"
		detail.Reason = "health"
		detail.Code = "HEALTH_STATUS_UNHEALTHY"
	}
	return owner, kind, detail
}

func (r *Runtime) dockerEventActionReason(ctx context.Context, target eventlog.Target, detail *eventlog.Detail, nano int64) {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return
	}
	r.controlPolicy.DiagnosticTaskReason(v.State, target, detail)
	if detail.Reason == "exit" || detail.Reason == "restart" || detail.Reason == "user" && detail.Operation == "" {
		r.checkerEventReason(target, detail, nano)
	}
}

// A certificate renewal or sfcd restart does not prove a node reboot. Use
// the actual OS boot identity/time, once per collector start. Missing procfs
// means unknown, never an invented node-restart reason.
func diagnosticBoot() (string, int64) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(raw) > 64 {
		return "", 0
	}
	id := strings.TrimSpace(string(raw))
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return "", 0
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(decoded) != 16 {
		return "", 0
	}
	stat, err := os.ReadFile("/proc/stat")
	if err != nil || len(stat) > 1<<20 {
		return "", 0
	}
	for _, line := range strings.Split(string(stat), "\n") {
		value, found := strings.CutPrefix(line, "btime ")
		if !found {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err == nil && seconds > 0 && seconds <= int64(^uint64(0)>>1)/int64(time.Second) {
			return id, seconds * int64(time.Second)
		}
	}
	return "", 0
}
