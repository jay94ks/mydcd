// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/nodedisks"
	"github.com/jay94ks/seafield/internal/observability"
)

// The diskfs spec comes from the record alone: copies in number order,
// members in recorded order, and a stopped bundle reads as missing.
func TestFuseSpecFromRecord(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	rec := nodedisks.BundleRecord{Schema: 1, Name: "slow", Backend: "fuse", Mode: "mirror", ID: "0102030405060708090a0b0c0d0e0f10", Allocation: "grow", Operation: "o", At: 1, Members: []nodedisks.BundleMemberRecord{
		{Disk: "sdc", Part: "sdc1", UUID: "u-c", Bytes: 100 << 20, Copy: 2, Dir: dirB},
		{Disk: "sdb", Part: "sdb1", UUID: "u-b", Bytes: 100 << 20, Copy: 1, Dir: dirA},
	}}
	if !rec.Valid() {
		t.Fatal("record")
	}
	spec, err := fuseSpec(rec)
	if err != nil || len(spec.Copies) != 2 || spec.Copies[0][0].Dir != dirA || spec.Copies[1][0].Part != "sdc1" || spec.ID[0] != 1 || spec.ID[15] != 0x10 {
		t.Fatal("spec", spec, err)
	}
	rec.ID = "zz"
	if _, err := fuseSpec(rec); err == nil {
		t.Fatal("bad ID accepted")
	}
	rec.ID = "0102030405060708090a0b0c0d0e0f10"
	rec.Name = "sfc-test-not-running"
	states := fuseBundles([]nodedisks.BundleRecord{rec}, observability.Devices{})
	if len(states) != 1 || states[0].State != "missing" || len(states[0].Members) != 2 || states[0].Members[0].State != "missing" || states[0].Members[0].Size != 100<<20 {
		t.Fatal("states", states)
	}
}

// A failed bundle activation waits before the next try, unless the disks
// changed; a success clears it.
func TestBundleActivationRetry(t *testing.T) {
	d := &nodeDiskRuntime{retries: map[string]activationRetry{}, diskSet: "sdb/S-B"}
	if !d.retryDue("pool") {
		t.Fatal("first try")
	}
	d.retry("pool", errors.New("no"))
	if d.retryDue("pool") {
		t.Fatal("retried at once")
	}
	d.diskSet = "sdb/S-B,sdc/S-C"
	if !d.retryDue("pool") {
		t.Fatal("a new disk should allow a try")
	}
	d.retry("pool", errors.New("no"))
	if d.retries["pool"].wait != 2*time.Minute {
		t.Fatal("backoff", d.retries["pool"].wait)
	}
	d.retry("pool", nil)
	if !d.retryDue("pool") {
		t.Fatal("cleared")
	}
}
