// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"testing"
	"time"
)

// Any packet from an authenticated peer moves LastReceived forward; it is
// keyed by the member ID Raft uses.
func TestLastReceivedFollowsPackets(t *testing.T) {
	p := topicWirePair(t, TopicACL{})
	server := p.pub.t
	first := server.LastReceived("consumer")
	if first.IsZero() || time.Since(first) > 5*time.Second {
		t.Fatalf("no contact after authentication: %v", first)
	}
	if !server.LastReceived("nobody").IsZero() {
		t.Fatal("contact for an unknown peer")
	}
	time.Sleep(20 * time.Millisecond)
	ctx := testCtx(t)
	sub, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if !server.LastReceived("consumer").After(first) {
		t.Fatal("a received packet did not move LastReceived")
	}
	if keepAlivePeriod != 10*time.Second || idleTimeout != 30*time.Second {
		t.Fatal("ping after 10s of silence, lost after 30s (Jay 2026-11-28)")
	}
}
