// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
)

// observedTaskFixture deploys source-app and records its web task's
// observation with the given log driver.
func observedTaskFixture(t *testing.T, driver string) (*backupCoreFixture, deployment.Observation, containerops.Selection) {
	t.Helper()
	f, _ := fieldCASFixture(t)
	managedDNSTaskCoreProgress(t, f, "source-app", "bind-inputs", deployment.ResourceKey("task", "tenant", "source-app", "web"), nil)
	apps, _ := f.p.Apps(f.s)
	e, _ := apps.Execution("tenant", "source-app")
	key := deployment.ResourceKey("task", "tenant", "source-app", "web")
	stage, found := e.Stage(key)
	if !found || stage.Observation == nil {
		t.Fatal("missing original task observation")
	}
	o := *stage.Observation
	o.LogDriver, o.StartedAt = driver, int64(time.Second)
	o.Sequence++
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", key, &o)
	return f, o, containerops.Selection{App: "source-app", Service: "web"}
}
