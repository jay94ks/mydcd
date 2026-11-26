// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/moby/moby/client"
)

// Reuses the real two-node/two-tenant fixture and its owned-resource rollback.
// Each viewer must obtain its own native detail/check/exit record, never the
// other tenant's records. Native effects are limited to these two exact Tasks.
func TestRQ4TwoTenantNativeDetailsChecksAndExitHistory(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("MYDC_NATIVE_MANIFEST") == "" || !filepath.IsAbs(os.Getenv("MYDC_DOCKER_TEST_BACKEND")) || os.Getenv("MYDC_DOCKER_TEST_CIDR") == "" {
		t.Skip("requires owned native rollback baseline and prepared backend")
	}
	testRealManagedJoin(t, false, "details-native")
}

func verifyTwoTenantDetailsNative(t *testing.T, ctx context.Context, runtimes []*Runtime, user userauth.Client, peer mydcp.Peer, readers []access.Session, wait func(string, func() bool)) {
	t.Helper()
	query := containerops.Query{Schema: 1, Kind: "inspect", Selection: containerops.Selection{App: "app", Service: "web"}, MaxBytes: containerops.MaxOutput, HistoryLimit: 20}
	for i, tenant := range []string{"first", "second"} {
		var target containerops.Target
		wait("tenant "+tenant+" actual detail and Docker health record", func() bool {
			reply, err := user.InspectContainer(ctx, peer, readers[i], tenant, query)
			if err != nil || reply.Container == nil || reply.Container.Detail == nil {
				return false
			}
			detail := reply.Container.Detail
			target = reply.Container.Target
			if target.Tenant != tenant || target.NativeID == "" || target.Owner != runtimes[i].Identity.Public || detail.MemoryBytes != 64<<20 || !detail.Running {
				t.Fatal("tenant native detail/owner mismatch", tenant)
			}
			for _, check := range detail.Checks {
				if check.Checker == "docker-health" && check.Status == "pass" && !check.At.IsZero() && check.DurationMS >= 0 && check.NativeID == target.NativeID {
					return true
				}
			}
			return false
		})
		foreign := "second"
		if i == 1 {
			foreign = "first"
		}
		if _, err := user.InspectContainer(ctx, peer, readers[i], foreign, query); err == nil {
			t.Fatal("foreign tenant detail/check/history returned", tenant, foreign)
		}
		api, err := runtimes[i].docker.StreamingAPI()
		if err != nil {
			t.Fatal(err)
		}
		killedAt := time.Now()
		if _, err = api.ContainerKill(ctx, target.NativeID, client.ContainerKillOptions{Signal: "SIGKILL"}); err != nil {
			t.Fatal("owned tenant native forced exit", err)
		}
		wait("tenant "+tenant+" actual exit137 history", func() bool {
			reply, err := user.InspectContainer(ctx, peer, readers[i], tenant, query)
			if err != nil || reply.Container == nil || reply.Container.Detail == nil {
				return false
			}
			if reply.Container.Target.NativeID != target.NativeID {
				t.Fatal("original tenant Task identity changed")
			}
			for _, row := range reply.Container.Detail.History {
				if row.NativeID != target.NativeID {
					t.Fatal("foreign native in tenant history")
				}
				if row.Kind == "task-exited" && row.At.UnixMilli() >= killedAt.UnixMilli() && row.ExitCode != nil && *row.ExitCode == 137 && row.Reason == "exit" {
					return true
				}
			}
			return false
		})
		t.Log("tenant detail, real health record, exit137 history and cross-tenant refusal", tenant, target.Node, target.NativeID)
	}
}
