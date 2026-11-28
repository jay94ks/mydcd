// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/vps"
)

type pickerProvider struct {
	vps.OwnedProvider // only Subscription is called
	ends              map[string]time.Time
}

func (p pickerProvider) Subscription(_ context.Context, id string) (vps.Subscription, error) {
	end, ok := p.ends[id]
	if !ok {
		return vps.Subscription{}, &vps.Error{Kind: vps.KindNotFound, Code: "NO_SUBSCRIPTION"}
	}
	return vps.Subscription{ExpiresAt: end}, nil
}

func TestOwnedPicker(t *testing.T) {
	end := time.Unix(1_800_000_000, 0)
	p := pickerProvider{ends: map[string]time.Time{"101": end}}
	list := []vps.Instance{
		{ID: "102", Flavor: "KVM 2", Zone: "nl", PublicIPv4: "203.0.113.12", Image: "Ubuntu 24.04", Status: vps.StatusOff},
		{ID: "101", Flavor: "KVM 1", Zone: "us", PublicIPv4: "203.0.113.11", Image: "Ubuntu 24.04", Status: vps.StatusActive},
	}
	owned := control.OwnedVPSCatalog{Servers: []control.OwnedVPS{
		{Name: "edge-1", Account: "home", InstanceID: "101"},
		{Name: "other", Account: "work", InstanceID: "102"}, // another account's VM with the same ID
	}}
	got := ownedPicker(t.Context(), p, "home", list, owned)
	if len(got) != 2 || got[0].ID != "101" || got[1].ID != "102" {
		t.Fatalf("order = %+v", got)
	}
	if got[0].Attached != "edge-1" || got[0].ExpiresAt != end.Unix() || got[0].Plan != "KVM 1" || got[0].Status != "active" {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].Attached != "" || got[1].ExpiresAt != 0 || got[1].Status != "off" || got[1].Zone != "nl" {
		t.Fatalf("second = %+v", got[1])
	}
	many := make([]vps.Instance, ownedPickerMax+5)
	for i := range many {
		many[i].ID = string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if n := len(ownedPicker(t.Context(), p, "home", many, owned)); n != ownedPickerMax {
		t.Fatalf("capped = %d", n)
	}
}
