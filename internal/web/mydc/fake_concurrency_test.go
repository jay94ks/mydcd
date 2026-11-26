// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"sync"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// Conn methods may be called concurrently (R03): one Conn, many callers.
func TestConnConcurrentCalls(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = admin.Whoami(ctx)
				_, _ = admin.Members(ctx, "")
				_, _ = admin.Tenants(ctx)
				_, _ = admin.NodeShellPolicy(ctx)
				_, _ = admin.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{})
				_, _ = admin.PlanNodeRemoval(ctx, "node-c")
				_, _ = admin.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: "node-b"})
				_, _ = seedEvents(admin, "", "")
				_, _ = admin.Session()
				_ = Reconnects(admin)
				if j%5 == 0 {
					op, err := admin.Prepare(ctx, Change{Action: ActionOpenNodeShell, Payload: mustPayload(t, OpenNodeShell{Node: "node-b", Cols: 80, Rows: 24})}, rootFor(t, admin, ActionOpenNodeShell))
					if err == nil {
						if sh, err := openShell(t, admin, op); err == nil {
							_ = sh.Close()
						}
					}
				}
			}
		}(i)
	}
	wg.Wait()
}
