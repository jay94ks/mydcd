// SPDX-License-Identifier: Apache-2.0

package store

import (
	"path/filepath"
	"reflect"
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
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

// A DNS domain's changes reach the workspaces it is or was assigned to; an
// unchanged reach check says nothing.
func TestStoreDNSAndACMEChanges(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var got []Change
	s.OnChange(func(c Change) { got = append(got, c) })
	d := &DNSDomain{Domain: "shop.example", Provider: "p", Assignments: []DNSAssignment{{Tenant: "a", Names: []string{"shop"}}}}
	if err := s.CreateDNSDomain(d); err != nil {
		t.Fatal(err)
	}
	d.Assignments = []DNSAssignment{{Tenant: "b", Names: []string{"shop"}}}
	if err := s.PutDNSDomain(d); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDNSHistory(&DNSHistory{Domain: "shop.example", ID: "h1", At: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateDNSServerLinks("shop.example", 0, func(l *DNSServerLinks) error {
		l.Rows["n1"] = &DNSServerLink{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reach := map[string]*DNSReach{"n1": {OK: true, At: time.Unix(2, 0)}}
	if err := s.SetDNSReach("shop.example", reach); err != nil {
		t.Fatal(err)
	}
	reach["n1"] = &DNSReach{OK: true, At: time.Unix(3, 0)}
	if err := s.SetDNSReach("shop.example", reach); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateACMECert(&ACMECert{Name: "c1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDNSDomain("shop.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTrash(&TrashItem{ID: "t1", Tenant: "a", ExpiresAt: time.Unix(10, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeTrash("t1"); err != nil {
		t.Fatal(err)
	}
	key, err := s.PutArchived(&ArchivedApp{Tenant: "a", App: "web", DownAt: time.Unix(5, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteArchived(key); err != nil {
		t.Fatal(err)
	}
	want := []Change{
		{Kind: "dns-domain", ID: "shop.example", Tenants: []string{"a"}},
		{Kind: "dns-domain", ID: "shop.example", Tenants: []string{"a", "b"}},
		{Kind: "dns-domain", ID: "shop.example", Tenants: []string{"b"}},
		{Kind: "dns-domain", ID: "shop.example", Tenants: []string{"b"}},
		{Kind: "dns-domain", ID: "shop.example", Tenants: []string{"b"}},
		{Kind: "acme-cert", ID: "c1"},
		{Kind: "dns-domain", ID: "shop.example", Tenants: []string{"b"}, Deleted: true},
		{Kind: "trash", Tenant: "a", ID: "t1"},
		{Kind: "trash", Tenant: "a", ID: "t1", Deleted: true},
		{Kind: "archived-app", Tenant: "a", ID: "web"},
		{Kind: "archived-app", Tenant: "a", ID: "web"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}
