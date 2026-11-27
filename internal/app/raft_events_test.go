// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestRQ4RaftEventUsesActualSDKTermAndNode(t *testing.T) {
	testRealManagedJoin(t, false, "raft-events")
}

func verifyRaftEventIdentity(t *testing.T, ctx context.Context, r *Runtime, c userauth.Client, admin access.Session, peer sfcp.Peer, wait func(string, func() bool)) {
	t.Helper()
	wait("actual SDK candidate event identity", func() bool {
		page, err := c.EventsPage(ctx, peer, admin, eventlog.Query{Kind: "quorum-degraded", Limit: 100})
		if err != nil {
			return false
		}
		observations, _ := r.Engine().ElectionObservations()
		for _, event := range page.Items {
			if event.Target.Node != r.Engine().ObservedNodeID() {
				continue
			}
			for _, row := range observations {
				if row.Term == event.Target.Term && row.ObservedAt == event.At && row.Role == "candidate" {
					status, err := c.RaftStatus(ctx, peer, admin)
					if err != nil || status.RaftStatus == nil || status.RaftStatus.ObservedBy != event.Target.Node {
						t.Fatal("event/raft-status observer identity mismatch", err)
					}
					t.Log("actual SDK observer and User event keep same node, term and observation time", event.Target.Node, event.Target.Term, event.At)
					return true
				}
			}
		}
		return false
	})
}
