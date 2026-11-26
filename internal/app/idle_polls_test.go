// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestEventPeerCurrentSkipsOnlyAConfirmedIdlePeer(t *testing.T) {
	now := time.Now()
	stream := [16]byte{1}
	synced := eventPeerSynced{Stream: stream, Last: 7, At: now.Add(-10 * time.Second)}
	if !eventPeerCurrent(synced, stream, 7, now) {
		t.Fatal("peer holding every own record was asked again")
	}
	for name, c := range map[string]struct {
		synced eventPeerSynced
		stream [16]byte
		own    uint64
		now    time.Time
	}{
		"never confirmed":       {eventPeerSynced{}, stream, 0, now},
		"new own record":        {synced, stream, 8, now},
		"new local stream":      {synced, [16]byte{2}, 7, now},
		"receipt older than 1m": {synced, stream, 7, now.Add(eventPeerRecheck)},
	} {
		if eventPeerCurrent(c.synced, c.stream, c.own, c.now) {
			t.Errorf("%s: skipped a peer that may be behind", name)
		}
	}
}

func TestNodeShellBookQuietOnlyWhenOffAndNothingOpen(t *testing.T) {
	off := control.NodeShellBook{}
	if !nodeShellBookQuiet(off, "node-a") {
		t.Fatal("disabled node shell with no sessions is not quiet")
	}
	on := control.NodeShellBook{Policy: access.NodeShellPolicy{Enabled: true}}
	if nodeShellBookQuiet(on, "node-a") {
		t.Fatal("enabled node shell must keep refreshing readiness")
	}
	onlyHere := control.NodeShellBook{Policy: access.NodeShellPolicy{Nodes: []access.NodeShellNode{{Node: "node-a", Shell: "on"}}}}
	if nodeShellBookQuiet(onlyHere, "node-a") || !nodeShellBookQuiet(onlyHere, "node-b") {
		t.Fatal("per-node override not honoured")
	}
	for _, state := range []string{"queued", "opened", "closing"} {
		b := control.NodeShellBook{Records: []control.NodeShellRecord{{Session: control.NodeShellSession{Node: "node-a", State: state}}}}
		if nodeShellBookQuiet(b, "node-a") {
			t.Errorf("%s session for this node left the loop quiet", state)
		}
		if !nodeShellBookQuiet(b, "node-b") {
			t.Errorf("%s session for another node kept this node busy", state)
		}
	}
	closed := control.NodeShellBook{Records: []control.NodeShellRecord{{Session: control.NodeShellSession{Node: "node-a", State: "closed"}}}}
	if !nodeShellBookQuiet(closed, "node-a") {
		t.Fatal("closed history kept the loop busy")
	}
}

func TestCheckerCacheDueOnRootChangeOrInterval(t *testing.T) {
	now := time.Now()
	root := checkerCacheRoot{Epoch: 3, Revision: 9}
	if !checkerCacheDue(now, time.Time{}, root, checkerCacheRoot{}) {
		t.Fatal("first collection not due")
	}
	if checkerCacheDue(now, now.Add(time.Minute), root, root) {
		t.Fatal("collected again with an unchanged lifecycle root before the interval")
	}
	if !checkerCacheDue(now, now.Add(time.Minute), checkerCacheRoot{Epoch: 3, Revision: 10}, root) {
		t.Fatal("lifecycle root change did not trigger collection")
	}
	if !checkerCacheDue(now, now.Add(time.Minute), checkerCacheRoot{Epoch: 4, Revision: 9}, root) {
		t.Fatal("module epoch change did not trigger collection")
	}
	if !checkerCacheDue(now, now, root, root) {
		t.Fatal("interval elapsed but collection not due")
	}
}
