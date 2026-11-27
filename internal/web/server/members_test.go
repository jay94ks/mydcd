// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// stuckMembers answers every members read with the same page and cursor.
type stuckMembers struct {
	sfc.Conn
	calls int
}

func (c *stuckMembers) Members(context.Context, string) (sfc.MembersPage, error) {
	c.calls++
	return sfc.MembersPage{Entries: []membership.Entry{{Peer: config.Peer{ID: "node-a"}}}, Next: "node-a"}, nil
}

func TestEachMemberStopsOnStuckCursor(t *testing.T) {
	c := &stuckMembers{}
	seen := 0
	if err := eachMember(context.Background(), c, func(memberView, sfc.MembersPage) bool { seen++; return true }); err != nil {
		t.Fatal(err)
	}
	if c.calls != 2 || seen != 2 {
		t.Fatalf("calls %d seen %d", c.calls, seen)
	}
}
