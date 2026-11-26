// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFakeCARejectsMissingTXT(t *testing.T) {
	ca := NewFakeCA()
	txt := map[string][]string{}
	ca.Lookup = func(_ context.Context, fqdn string) ([]string, error) { return txt[fqdn], nil }
	key, _ := NewKey(EC256)
	acct, _ := ca.Register(context.Background(), key, "", nil)
	o, err := ca.NewOrder(context.Background(), key, acct, []string{"a.example.com", "*.a.example.com"}, nil)
	if err != nil || len(o.Challenges) != 2 || o.Challenges[1].TXTName != "_acme-challenge.a.example.com" {
		t.Fatalf("order: %+v %v", o, err)
	}
	if err := ca.Validate(context.Background(), key, acct, o); !errors.Is(err, ErrRejected) {
		t.Fatalf("validated without TXT: %v", err)
	}
	ck, _ := NewKey(EC256)
	csr, _ := CSR(ck, o.Names)
	if _, err := ca.Finalize(context.Background(), key, acct, o, csr); err == nil {
		t.Fatal("finalized before validation")
	}
	for _, c := range o.Challenges {
		txt[c.TXTName] = append(txt[c.TXTName], c.TXTValue)
	}
	if err := ca.Validate(context.Background(), key, acct, o); err != nil {
		t.Fatal(err)
	}
	other, _ := NewKey(EC256)
	bad, _ := CSR(other, []string{"b.example.com"})
	if _, err := ca.Finalize(context.Background(), key, acct, o, bad); err == nil {
		t.Fatal("CSR with other names accepted")
	}
	chain, err := ca.Finalize(context.Background(), key, acct, o, csr)
	if err != nil {
		t.Fatal(err)
	}
	ci, err := Inspect(chain, EC256)
	if err != nil || len(ci.Names) != 2 || ci.NotAfter.Sub(ci.NotBefore) < 89*24*time.Hour {
		t.Fatalf("cert: %+v %v", ci, err)
	}
	if r := RenewAt(ci.NotBefore, ci.NotAfter); ci.NotAfter.Sub(r) < 29*24*time.Hour {
		t.Fatalf("renew at %v", r)
	}
}
