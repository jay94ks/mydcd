// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/tests/clusterfixture"
)

// Two real mydcd nodes on fake Docker engines: the web adapter reaches the
// cluster through either node's management socket, sees both voters, and
// each node's workload report comes from its own engine.
func TestRealTwoNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real mydcd nodes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := clusterfixture.New(t, ctx, 2)
	for _, n := range c.Nodes {
		client, err := NewReal(RealConfig{Socket: n.Socket, Cluster: c.ID, Node: n.ID, NodeKey: n.Key})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		realKeyLogin(t, ctx, conn, "admin", c.Admin.Private)
		members, err := conn.Members(ctx, "")
		if err != nil || members.NodeVoters != 2 || len(members.Entries) != 2 {
			t.Fatalf("%s members: %+v %v", n.ID, members, err)
		}
		for _, e := range members.Entries {
			if e.Phase != membership.Active || !e.Peer.Voter {
				t.Fatalf("%s entry %+v", n.ID, e)
			}
		}
		// Node reports arrive on their own schedule (every 30s; the joined
		// node's first one can come before it is active, so this waits up to
		// one period). A node is ready once its engine answered Info and its
		// container list.
		c.Wait(n.ID+" ready nodes", func() bool {
			page, err := conn.NodeSummary(ctx, "", "", "")
			if err != nil || len(page.Nodes) != 2 {
				return false
			}
			for _, s := range page.Nodes {
				if !s.Ready {
					return false
				}
			}
			return true
		})
	}
}
