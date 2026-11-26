// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/membership"
)

// liveMember: one server as `members` reports it, the entry and its
// lifecycle row joined by ID. Phase is the lifecycle phase ("pending"
// without a row); Revision the entry's (the fake keeps one revision).
type liveMember struct {
	Revision   uint64
	Phase      string
	Voter      bool
	Join       membership.Phase
	Scheduling membership.CordonView
}

func liveMemberOf(t *testing.T, c Conn, id string) liveMember {
	t.Helper()
	after := ""
	for {
		p, err := c.Members(ctx, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Entries {
			if e.Peer.ID != id {
				continue
			}
			m := liveMember{Revision: e.Revision, Phase: NodePhasePending, Voter: e.Peer.Voter, Join: e.Phase}
			for _, v := range p.Nodes {
				if v.Node.Member.ID == id {
					m.Phase, m.Voter, m.Scheduling = string(v.Node.Phase), v.Node.Member.Voter, v.Scheduling
				}
			}
			return m
		}
		if p.Next == "" {
			t.Fatal("no member " + id)
		}
		after = p.Next
	}
}
