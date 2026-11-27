// SPDX-License-Identifier: Apache-2.0

package store

import (
	"path/filepath"
	"testing"
	"time"
)

// Committed writes of the records the live socket reports name the record,
// with the tenant that decides who hears of it; failed writes say nothing.
func TestStoreChangesNameRecords(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var got []Change
	s.OnChange(func(c Change) { got = append(got, c) })
	if err := s.CreateWebhook(&Webhook{Name: "hook", Tenant: "shop"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateWebhook(&Webhook{Name: "hook", Tenant: "shop"}); err != ErrConflict {
		t.Fatal(err)
	}
	if err := s.PutWebhookLink(&WebhookLink{ID: "l1", Webhook: "hook", CreatedAt: time.Now()}, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveGuide(&Guide{Scope: "app/shop/web", Tenant: "shop"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGuide("app/shop/web"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteWebhook("hook"); err != nil {
		t.Fatal(err)
	}
	want := []Change{
		{Kind: "webhook", Tenant: "shop", ID: "hook"},
		{Kind: "webhook-link", Tenant: "shop", ID: "l1"},
		{Kind: "guide", Tenant: "shop", ID: "app/shop/web"},
		{Kind: "guide", Tenant: "shop", ID: "app/shop/web", Deleted: true},
		{Kind: "webhook", Tenant: "shop", ID: "hook", Deleted: true},
	}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(i, got[i], want[i])
		}
	}
}
