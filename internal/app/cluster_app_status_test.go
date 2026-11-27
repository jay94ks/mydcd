// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/clusterapp"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func TestClusterAppReportsFollowTheContainer(t *testing.T) {
	ctx := context.Background()
	none := func(string) (clusterapp.Release, error) { return clusterapp.Release{}, clusterapp.ErrImageNotFound }
	if got := clusterAppReports(ctx, nil, none, nil); len(got) != 0 {
		t.Fatal("no cluster app turned on", got)
	}
	got := clusterAppReports(ctx, []string{clusterapp.Web, "unknown"}, none, nil)
	if len(got) != 1 || got[0].Name != clusterapp.Web || got[0].Control != "node-config" || got[0].Image != "sfc/web" || len(got[0].Ports) != 3 || got[0].Ports[0].Port != clusterapp.WebPort || got[0].Ports[1].Port != clusterapp.WebACMEPort || got[0].Ports[2].Port != clusterapp.WebDirectPort {
		t.Fatalf("rows: %+v", got)
	}
	if got[0].State != "image-not-found" || got[0].Reason != "image-not-installed" || got[0].Digest != "" {
		t.Fatalf("no image package: %+v", got[0])
	}
	untrusted := func(string) (clusterapp.Release, error) { return clusterapp.Release{}, clusterapp.ErrRelease }
	if got := clusterAppReports(ctx, []string{clusterapp.Web}, untrusted, nil); got[0].State != "image-mismatch" || got[0].Reason != "release-unverified" {
		t.Fatalf("untrusted manifest: %+v", got[0])
	}
	signed := func(string) (clusterapp.Release, error) {
		return clusterapp.Release{Schema: 1, App: "web", Repository: "sfc/web", Version: "0.9.1", Digest: "sha256:" + strings.Repeat("a", 64)}, nil
	}
	if got := clusterAppReports(ctx, []string{clusterapp.Web}, signed, nil); got[0].State != "starting" || got[0].Version != "0.9.1" || got[0].Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("no container yet: %+v", got[0])
	}
	live := func(context.Context, string) (clusterAppLive, bool) {
		return clusterAppLive{Docker: "running", Address: "10.254.1.3", Restarts: 2}, true
	}
	if got := clusterAppReports(ctx, []string{clusterapp.Web}, signed, live); got[0].State != "running" || got[0].Address != "10.254.1.3" || got[0].Restarts != 2 {
		t.Fatalf("live: %+v", got[0])
	}
	if got := clusterAppReports(ctx, []string{clusterapp.Web}, untrusted, live); got[0].State != "image-mismatch" {
		t.Fatalf("live container must not hide an untrusted manifest: %+v", got[0])
	}
	if got := (&Runtime{}); got != nil {
		if _, ok := got.clusterAppLiveState(ctx, clusterapp.Web); ok {
			t.Fatal("live state without a container owner")
		}
	}
	for docker, want := range map[string]string{"created": "starting", "running": "running", "restarting": "restarting", "removing": "stopping", "exited": "exited", "dead": "failed", "paused": "failed", "": "starting"} {
		if s := clusterAppState(docker); s != want {
			t.Fatal(docker, s, want)
		}
	}
}

// A reconcile problem shows instead of a misleading starting, and wins over
// an old container that still runs.
func TestClusterAppProblemsShowInTheReport(t *testing.T) {
	for err, want := range map[error][2]string{
		nil: {"", ""},
		fmt.Errorf("cluster app web: %w", clusterapp.ErrImageNotFound):        {"image-not-found", "image-not-installed"},
		fmt.Errorf("cluster app web: %w", clusterapp.ErrImage):                {"image-mismatch", "image-digest-mismatch"},
		fmt.Errorf("cluster app web: %w", clusterapp.ErrRelease):              {"image-mismatch", "release-unverified"},
		fmt.Errorf("x: %w: %w", errClusterAppImageLoad, errors.New("engine")): {"failed", "image-load-failed"},
		errors.New("engine"): {"failed", "reconcile-failed"},
		fmt.Errorf("x: %w", errors.Join(errors.New("cluster app container not created"), reconcile.ErrLease)): {"starting", "system-network-pending"},
		fmt.Errorf("x: %w", reconcile.ErrPending):                                                             {"starting", "system-network-pending"},
	} {
		if s, r := clusterAppOutcome(err); s != want[0] || r != want[1] {
			t.Fatal(err, s, r)
		}
	}
	var p clusterAppProblems
	p.set("web", "image-not-found", "image-not-installed")
	if s, r := p.get("web"); s != "image-not-found" || r != "image-not-installed" {
		t.Fatal(s, r)
	}
	p.set("web", "", "")
	if s, _ := p.get("web"); s != "" {
		t.Fatal("not cleared", s)
	}
	row := observability.ClusterApp{Name: "web", State: "starting"}
	if got := withClusterAppLive(row, clusterAppLive{Docker: "running", Address: "10.254.1.3", Restarts: 2}); got.State != "running" || got.Address != "10.254.1.3" || got.Restarts != 2 {
		t.Fatalf("running: %+v", got)
	}
	if got := withClusterAppLive(row, clusterAppLive{Docker: "running", State: "image-not-found", Reason: "image-not-installed"}); got.State != "image-not-found" || got.Reason != "image-not-installed" {
		t.Fatalf("problem hidden: %+v", got)
	}
	if got := withClusterAppLive(row, clusterAppLive{State: "unknown", Reason: "status-unavailable"}); got.State != "unknown" {
		t.Fatalf("unknown: %+v", got)
	}
	if got := withClusterAppLive(row, clusterAppLive{}); got.State != "starting" {
		t.Fatalf("no container yet: %+v", got)
	}
}
