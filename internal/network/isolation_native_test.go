// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/jay94ks/mydcd/internal/engine"
)

// Native nft transaction/readback only, guarded by an owned namespace. The
// two-owner Docker/packet fixture must prove real service access/default deny.
func TestRealBoundaryTenantIsolationOwnedAtomicPolicy(t *testing.T) {
	host, authority := os.Getenv("MYDC_KERNEL_HOST_NETNS"), os.Getenv("MYDC_KERNEL_TEST_OWNER")
	if host == "" {
		t.Skip("owned isolated network namespace and prior rollback plan required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || current == host || authority == "" || os.Geteuid() != 0 {
		t.Fatal("refuse unowned/host nft mutation", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	snapshot := func() []byte {
		t.Helper()
		raw, err := exec.CommandContext(ctx, "nft", "-j", "list", "ruleset").CombinedOutput()
		if err != nil {
			t.Fatal("isolation baseline/readback", err, string(raw))
		}
		return raw
	}
	before := snapshot()
	spec := managedIsolationFixture(t)
	spec.Owner = engine.Owner(sha256.Sum256([]byte(authority+"/cluster")), sha256.Sum256([]byte(authority+"/node")))
	spec, err = NormalizeIsolation(spec)
	if err != nil {
		t.Fatal(err)
	}
	target := spec
	target.Routes = nil
	target, err = NormalizeIsolation(target)
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := IsolationExists(spec.Owner); err != nil || exists {
		t.Fatal("isolation fixture table already exists", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, candidate := range []IsolationSpec{target, spec} {
			if err := RemoveIsolation(cleanup, candidate); err == nil {
				break
			}
		}
		if exists, err := IsolationExists(spec.Owner); err != nil || exists {
			t.Error("owned isolation rollback incomplete", exists, err)
		}
		raw, err := exec.CommandContext(cleanup, "nft", "-j", "list", "ruleset").CombinedOutput()
		if err != nil || !bytes.Equal(before, raw) {
			t.Error("isolation nft baseline not restored", err, string(raw))
		}
	})
	if err := ApplyIsolation(ctx, nil, spec, false); !errors.Is(err, ErrKernelOwnership) {
		t.Fatal("recovery created an absent original table", err)
	}
	if err := ApplyIsolation(ctx, nil, spec, true); err != nil {
		t.Fatal("initial own isolation policy", err)
	}
	if err := ApplyIsolation(ctx, nil, spec, false); err != nil {
		t.Fatal("same operation ACK replay/readback", err)
	}
	c, table, err := lookupOwnedFirewall(isolationRules(spec))
	if err != nil || table == nil {
		t.Fatal(err)
	}
	want := isolationRules(spec)
	fault := &nftables.Rule{Table: table, Chain: want.chains[1], Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}}, UserData: []byte("mydc-isolation-owned-fault-1")}
	// Register before the fault write; an unknown ACK must still roll back.
	t.Cleanup(func() {
		exists, err := IsolationExists(spec.Owner)
		if err != nil {
			t.Error(err)
			return
		}
		if !exists {
			return
		}
		fresh := &nftables.Conn{}
		rules, err := fresh.GetRules(table, want.chains[1])
		if err != nil {
			t.Error(err)
			return
		}
		for _, rule := range rules {
			if bytes.Equal(rule.UserData, fault.UserData) {
				if err := fresh.DelRule(rule); err != nil {
					t.Error(err)
				}
			}
		}
		if err := fresh.Flush(); err != nil {
			t.Error(err)
		}
	})
	c.AddRule(fault)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := ApplyIsolation(ctx, &spec, target, false); !errors.Is(err, ErrKernelOwnership) {
		t.Fatal("foreign rule was adopted/replaced", err)
	}
	// AddRule does not provide a readback handle; remove only the exact fault
	// rule obtained from the kernel, then the regular strict adapter proceeds.
	rules, err := c.GetRules(table, want.chains[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if bytes.Equal(rule.UserData, fault.UserData) {
			if err := c.DelRule(rule); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := ApplyIsolation(ctx, &spec, target, false); err != nil {
		t.Fatal("owned policy atomic withdrawal", err)
	}
	if present, err := InspectIsolation(target); err != nil || !present {
		t.Fatal("new exact isolation readback", err)
	}
	if present, err := InspectIsolation(spec); err == nil || present {
		t.Fatal("old policy was reported applied after replacement")
	}
	if err := RemoveIsolation(ctx, target); err != nil {
		t.Fatal(err)
	}
	if exists, err := IsolationExists(spec.Owner); err != nil || exists {
		t.Fatal("original table not Gone", err)
	}
	if err := ApplyIsolation(ctx, &target, spec, true); !errors.Is(err, ErrKernelOwnership) {
		t.Fatal("new update recreated a missing previously applied table", err)
	}
	raw, _ := json.Marshal(target)
	t.Logf("own isolation table transaction/readback, namespace=%s owner=%s final=%s", current, authority, raw)
}
