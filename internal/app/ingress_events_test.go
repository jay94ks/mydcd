// SPDX-License-Identifier: Apache-2.0

package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/storage"
)

func TestIngressCertificateEventsUseSignedDurableJournal(t *testing.T) {
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	path := filepath.Join(t.TempDir(), "original-events.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	cluster := [32]byte{91}
	store, err := eventlog.Open(db, cluster, "node-a", self)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{events: store}
	now := uint64(time.Now().UnixMilli())
	kinds := []string{"cert-expiring", "cert-expired", "ingress-certificate-missing"}
	for index, kind := range kinds {
		e := ingress.Event{Kind: kind, Node: "node-a", Tenant: "tenant", App: "shop", RouteID: "web", Host: "shop.example", Prefix: "/", Gateway: "external", ObservedAt: now + uint64(index)}
		r.ingressEvent(e)
		r.ingressEvent(e) // same original event must retain one signed record
	}
	if r.moduleError != nil {
		t.Fatal("certificate event rejected by the actual journal", r.moduleError)
	}
	batch, err := store.Export(0, now+10)
	if err != nil || !batch.Valid() || len(batch.Records) != len(kinds) {
		t.Fatal("invalid signed source batch", err)
	}
	for index, record := range batch.Records {
		e := record.Event
		if !record.Valid() || e.Kind != kinds[index] || e.Scope != "app" || e.Target.Node != "node-a" || e.Target.Tenant != "tenant" || e.Target.App != "shop" || e.Target.RouteID != "web" || e.Target.Host != "shop.example" || e.Target.Gateway != "external" || e.Detail.Code != "INGRESS_OBSERVATION" {
			t.Fatal("durable certificate event changed source or public scope", e)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err = eventlog.Open(db, cluster, "node-a", self)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Export(0, now+11)
	if err != nil || len(reopened.Records) != len(batch.Records) {
		t.Fatal("original source records disappeared on reopen", err)
	}
	for index, record := range reopened.Records {
		if !record.Valid() || record.ID() != batch.Records[index].ID() {
			t.Fatal("reopen replaced an original signed certificate event")
		}
	}
}
