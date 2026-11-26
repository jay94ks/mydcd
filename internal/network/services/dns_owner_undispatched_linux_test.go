// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/workload"
)

// E4 final adapter bundle. Actual protected owner/Network/workload DBs, no
// Docker/Netlink/socket effects; the shared instance grant is fixture input.
func TestDNSOwnerUndispatchedRetirementKeepsOriginalJournalAndLifetime(t *testing.T) {
	d := newDNSFixture(t)
	d = grantDNS(t, d, d.cfg)
	d.cfg.Source++
	d.cfg.Serial++
	d.cfg.Enabled = false
	d = grantDNS(t, d, d.cfg)
	local, _ := source(d.f.n, d.f.a.cluster, d.cfg.Tenant, d.cfg.Network, d.cfg.Pool)
	ref, _ := d.f.a.DNSReference(d.cfg.Tenant, d.cfg.ID, local)
	root := t.TempDir()
	n, err := network.OpenManager(filepath.Join(root, "network.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	w, err := workload.OpenManager(filepath.Join(root, "workload.db"), nil, n)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	policy := DNSOwnerPolicy{Catalog: d.f.c, Networks: d.f.n, Authority: d.f.a, Actor: "admin", Config: d.cfg, Bridge: "network/original-unstarted-bridge", BridgeGeneration: local.NetworkGeneration, MaxConnections: 4, RequestTimeout: time.Second}
	options := DNSOwnerOptions{Cluster: d.f.a.cluster, Key: d.f.key, Network: n, Workload: w, Roots: []string{"mydc.test."}, MaxViews: 8, MaxQueries: 8, MaxConnections: 4, IdleTimeout: time.Second,
		Current: func(context.Context, string, string) (DNSOwnerPolicy, error) { return policy, nil },
		Permit: func(context.Context, DNSOwnerPolicy) error {
			t.Error("retirement requested a new native permit")
			return ErrLease
		},
	}
	path := filepath.Join(root, "dns.db")
	o, err := OpenDNSOwner(path, options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	proof, err := o.Retire(context.Background(), d.cfg.Tenant, d.cfg.ID)
	if err != nil || proof == nil || proof.Consumer != ref.ID || proof.Generation != ref.Generation || proof.Lifetime != ref.Lifetime || !validReferenceClose(d.f.a.cluster, ref, *proof) || !ed25519.Verify(ed25519.PublicKey(ref.Local.Owner[:]), ReferenceCloseBytes(*proof), proof.Signature) {
		t.Fatal("original undispatched instance closure", proof, err)
	}
	if len(o.sockets) != 0 || len(o.settings.scopes) != 0 || len(n.Keys()) != 0 {
		t.Fatal("closing an undispatched instance created native intent")
	}
	if _, err := d.f.a.ObserveReferenceClose(*proof, proof.At); err != nil {
		t.Fatal("real signed receipt did not satisfy original shared core", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = OpenDNSOwner(path, options)
	if err != nil {
		t.Fatal("same original DB", err)
	}
	again, err := o.Retire(context.Background(), d.cfg.Tenant, d.cfg.ID)
	if err != nil || again == nil || again.Consumer != proof.Consumer || again.Lifetime != proof.Lifetime {
		t.Fatal("reopen replaced original lifetime", again, err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if reset, err := OpenDNSOwner(path, options); err == nil {
		_ = reset.Close()
		t.Fatal("missing original journal became an undispatched fresh owner")
	}
}
