// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/observability"
)

func TestObservationEventsPreserveFilesystemAndMeshIdentifiers(t *testing.T) {
	filesystem := observability.FilesystemID("node-a", "public-filesystem")
	old := observability.Report{Node: "node-a", At: 1000, Disk: &observability.Disk{ID: filesystem, Total: 1000, Available: 100}}
	current := old
	current.At = 2000
	current.Disk = &observability.Disk{ID: filesystem, Total: 1000, Available: 99}
	rows := observationEvents(&old, current)
	if len(rows) != 1 || rows[0].Event.Kind != "node-resource-low" || rows[0].Event.Target.FilesystemID != filesystem || !rows[0].Event.Valid() {
		t.Fatal("disk event lost original filesystem identity")
	}
	if rows := observationEvents(&current, current); len(rows) != 0 {
		t.Fatal("unchanged low sample became repeated incidents")
	}
	pair := observability.PairID("node-a", "node-b")
	current = observability.Report{Node: "node-a", At: 12000, Link: &observability.Link{ID: pair, Peer: "node-b", State: "down", LastHandshakeAt: 1000, LastChangeAt: 2000, Outages: []observability.Outage{{StartedAt: 2000}}}}
	rows = observationEvents(nil, current)
	if len(rows) != 2 || rows[0].Event.Kind != "tunnel-down" || rows[1].Event.Kind != "node-unreachable" {
		t.Fatal("retained outage/unreachable signals missing")
	}
	for _, row := range rows {
		if row.Event.Target.PairID != pair || !row.Event.Valid() {
			t.Fatal("link event lost original PairID")
		}
	}
	current.At--
	if rows := observationEvents(nil, current); len(rows) != 1 || rows[0].Event.Kind != "tunnel-down" {
		t.Fatal("node unreachable emitted before down threshold")
	}
}

func TestMemoryEventRequiresMeasuredCrossing(t *testing.T) {
	total, before, after := uint64(1000), uint64(899), uint64(900)
	previous := observability.Report{Node: "node-a", At: 1000, Host: &observability.Host{MemoryTotal: &total, MemoryUsed: &before}}
	current := observability.Report{Node: "node-a", At: 2000, Host: &observability.Host{MemoryTotal: &total, MemoryUsed: &after}}
	rows := observationEvents(&previous, current)
	if len(rows) != 1 || rows[0].Event.Detail.Resource != "memory" || !rows[0].Event.Valid() {
		t.Fatal("memory crossing missing")
	}
	if len(observationEvents(&current, current)) != 0 {
		t.Fatal("unchanged memory sample repeated event")
	}
	current.Host.MemoryUsed = nil
	if len(observationEvents(&previous, current)) != 0 {
		t.Fatal("missing measurement fabricated resource risk")
	}
}
