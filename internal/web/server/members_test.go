// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// stuckMembers answers every members read with the same page and cursor.
type stuckMembers struct {
	mydc.Conn
	calls int
}

func (c *stuckMembers) Members(context.Context, string) (mydc.MembersPage, error) {
	c.calls++
	return mydc.MembersPage{Entries: []membership.Entry{{Peer: config.Peer{ID: "node-a"}}}, Next: "node-a"}, nil
}

func TestEachMemberStopsOnStuckCursor(t *testing.T) {
	c := &stuckMembers{}
	seen := 0
	if err := eachMember(context.Background(), c, func(memberView, mydc.MembersPage) bool { seen++; return true }); err != nil {
		t.Fatal(err)
	}
	if c.calls != 2 || seen != 2 {
		t.Fatalf("calls %d seen %d", c.calls, seen)
	}
}
