// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"
)

func TestLeaderLinkHeldSince(t *testing.T) {
	at := time.Now()
	was := leaderLink{ID: "node-b", Term: 4, Since: at.Add(-time.Minute)}
	for name, c := range map[string]struct {
		now  leaderLink
		want bool
	}{
		"same link":         {leaderLink{ID: "node-b", Term: 4, Since: was.Since}, true},
		"other leader":      {leaderLink{ID: "node-c", Term: 4, Since: was.Since}, false},
		"new term":          {leaderLink{ID: "node-b", Term: 5, Since: was.Since}, false},
		"reconnected after": {leaderLink{ID: "node-b", Term: 4, Since: at.Add(time.Second)}, false},
		"no link":           {leaderLink{ID: "node-b", Term: 4}, false},
		"self, same term":   {leaderLink{ID: "node-b", Term: 4, Self: true}, true},
		"no leader":         {leaderLink{}, false},
	} {
		if got := c.now.heldSince(was, at); got != c.want {
			t.Errorf("%s: heldSince = %t, want %t", name, got, c.want)
		}
	}
}
