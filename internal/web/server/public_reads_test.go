// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

func TestResourceUsersFold(t *testing.T) {
	yes, no := true, false
	rows := []control.PublicReadRow{
		{Key: "a", User: &control.PublicResourceUser{Kind: "app-service", App: "shop", Service: "web", Node: "n1", Task: "t1", ContainerPresent: &yes, EndpointPresent: &yes, Writable: &yes}},
		{Key: "b", User: &control.PublicResourceUser{Kind: "app-service", App: "shop", Service: "web", Node: "n1", Task: "t2", ContainerPresent: &yes, Writable: &no}},
		{Key: "c", User: &control.PublicResourceUser{Kind: "standalone", Standalone: "tmp", Node: "n2", ContainerPresent: &no}},
		{Key: "d", User: &control.PublicResourceUser{Kind: "volume-operation", Consumer: "backup-1", Node: "n1", Writable: &no}},
	}
	net, apps, sa := resourceUsers(rows, true)
	if len(net) != 3 || apps != 1 || sa != 1 {
		t.Fatalf("network fold = %+v apps %d standalones %d", net, apps, sa)
	}
	if !net[0].Attached || len(net[0].Selection) != 1 || net[0].Kind != sfc.NetworkUserService || !net[0].ReadOnly {
		t.Fatalf("service entry = %+v (one endpoint seen, one task read-only)", net[0])
	}
	if net[1].Attached || net[1].Kind != sfc.NetworkUserStandalone {
		t.Fatalf("standalone entry = %+v", net[1])
	}
	if net[2].Kind != "volume-operation" || net[2].Consumer != "backup-1" || net[2].Attached {
		t.Fatalf("operation entry = %+v", net[2])
	}
	vol, _, _ := resourceUsers(rows, false)
	if len(vol[0].Selection) != 2 {
		t.Fatalf("volume: both containers are present, got %+v", vol[0])
	}
}
