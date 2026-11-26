// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/observability"
)

type derivedObservationEvent struct {
	Tag   string
	Event eventlog.Event
}

func observationEvents(previous *observability.Report, current observability.Report) []derivedObservationEvent {
	var rows []derivedObservationEvent
	previousAt := uint64(0)
	if previous != nil {
		previousAt = previous.At
	}
	emit := func(tag, kind, scope string, at uint64, target eventlog.Target, detail eventlog.Detail) {
		rows = append(rows, derivedObservationEvent{Tag: tag, Event: eventlog.Event{Kind: kind, Scope: scope, At: at, Target: target, Detail: detail}})
	}
	if disk := current.Disk; disk != nil && disk.Available < disk.Total/10 {
		wasLow := previous != nil && previous.Disk != nil && previous.Disk.ID == disk.ID && previous.Disk.Available < previous.Disk.Total/10
		if !wasLow {
			emit(fmt.Sprintf("disk-low/%s/%d", disk.ID, previousAt), "node-resource-low", "node", current.At, eventlog.Target{Node: current.Node, FilesystemID: disk.ID}, eventlog.Detail{Code: "DISK_AVAILABLE_BELOW_TEN_PERCENT", Resource: "disk"})
		}
	}
	if host := current.Host; host != nil && host.MemoryUsed != nil && host.MemoryTotal != nil && *host.MemoryTotal > 0 {
		low := *host.MemoryUsed >= *host.MemoryTotal-*host.MemoryTotal/10
		wasLow := previous != nil && previous.Host != nil && previous.Host.MemoryUsed != nil && previous.Host.MemoryTotal != nil && *previous.Host.MemoryTotal > 0 && *previous.Host.MemoryUsed >= *previous.Host.MemoryTotal-*previous.Host.MemoryTotal/10
		if low && !wasLow {
			emit(fmt.Sprintf("memory-low/%d", previousAt), "node-resource-low", "node", current.At, eventlog.Target{Node: current.Node}, eventlog.Detail{Code: "MEMORY_USED_AT_LEAST_NINETY_PERCENT", Resource: "memory"})
		}
	}
	if link := current.Link; link != nil {
		for _, outage := range link.Outages {
			if outage.StartedAt == 0 {
				continue
			}
			emit(fmt.Sprintf("tunnel-down/%s/%d", link.ID, outage.StartedAt), "tunnel-down", "node", outage.StartedAt, eventlog.Target{Node: current.Node, PairID: link.ID}, eventlog.Detail{Code: "AUTHENTICATED_LINK_DOWN", State: "down"})
		}
		if link.State == "down" && link.LastHandshakeAt > 0 && current.At >= link.LastChangeAt && current.At-link.LastChangeAt >= 10000 {
			emit(fmt.Sprintf("node-unreachable/%s/%d", link.Peer, link.LastChangeAt), "node-unreachable", "node", current.At, eventlog.Target{Node: link.Peer, PairID: link.ID}, eventlog.Detail{Code: "PEER_LINK_UNREACHABLE", State: "down"})
		}
	}
	return rows
}

func (r *Runtime) appendObservationEvents(previous *observability.Report, current observability.Report) error {
	if r.events == nil || current.Key != r.Identity.Public {
		return nil
	}
	rows := observationEvents(previous, current)
	if current.Link != nil {
		// A transport outage is a fact about a node pair. Publish tenant/network
		// events only for actual current logical TUN memberships of that pair.
		// No raw node-scoped tunnel event is used as a tenant fallback.
		rows = slices.DeleteFunc(rows, func(row derivedObservationEvent) bool { return row.Event.Kind == "tunnel-down" })
		ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
		defer cancel()
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			return err
		}
		resources, err := r.controlPolicy.Resources(v.State)
		if err != nil {
			return err
		}
		rows = append(rows, networkTunnelEvents(current, resources.Networks)...)
	}
	now := uint64(time.Now().UnixMilli())
	for _, row := range rows {
		if row.Event.At < now && now-row.Event.At > eventlog.RetentionMillis {
			continue
		}
		if _, err := r.events.Append(row.Tag, row.Event, now); err != nil {
			return err
		}
	}
	return nil
}

// networkTunnelEvents uses the same network membership catalog as the TUN
// projection. Several tenants sharing a transport receive separate scoped facts.
func networkTunnelEvents(current observability.Report, networks tenancy.Networks) []derivedObservationEvent {
	if current.Link == nil {
		return nil
	}
	link := current.Link
	if link.ID != observability.PairID(current.Node, link.Peer) {
		return nil
	}
	members := networks.AllNetworks()
	seen := map[string]bool{}
	var out []derivedObservationEvent
	for _, local := range members {
		if local.Node != current.Node || local.Owner != current.Key || local.Logical == "" || local.Draining || len(local.TunnelAddresses) == 0 {
			continue
		}
		paired := false
		for _, peer := range members {
			paired = paired || peer.Node == link.Peer && peer.Tenant == local.Tenant && peer.Logical == local.Logical && !peer.Draining && len(peer.TunnelAddresses) > 0
		}
		key := local.Tenant + "/" + local.Logical
		if !paired || seen[key] {
			continue
		}
		seen[key] = true
		for _, outage := range link.Outages {
			if outage.StartedAt == 0 {
				continue
			}
			for _, edge := range []struct {
				kind, state string
				at          uint64
			}{{"tunnel-down", "down", outage.StartedAt}, {"tunnel-up", "up", outage.EndedAt}} {
				if edge.at == 0 {
					continue
				}
				tag := fmt.Sprintf("%s/%s/%s/%d", edge.kind, key, link.ID, outage.StartedAt)
				out = append(out, derivedObservationEvent{Tag: tag, Event: eventlog.Event{Kind: edge.kind, Scope: "tenant", At: edge.at, Target: eventlog.Target{Tenant: local.Tenant, Network: local.Logical, Node: current.Node, PairID: link.ID}, Detail: eventlog.Detail{Code: "AUTHENTICATED_LINK_" + map[string]string{"down": "DOWN", "up": "UP"}[edge.state], State: edge.state}}})
			}
		}
	}
	return out
}
