// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// REQ-28 in sfcd's real shape: plan → signed change → Submit → one
// purpose18 stream → status; folder grants with access.VolumeFileFolderGrant.
func TestVolumeFilesReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	const pre = "sfc-web-backups/"

	// plan + sign + submit; the reply of Submit must be Applied.
	reserve := func(c Conn, q control.VolumeFileQuery) (SignedOp, Result) {
		t.Helper()
		p, err := c.VolumeFilePlan(ctx, "shop", q)
		if err != nil {
			t.Fatalf("plan %s %v", q.Method, err)
		}
		return submit(t, c, q.Method, p.Revision, p.Change, rootFor(t, c, q.Method))
	}
	data := []byte("sealed web.db snapshot")
	sum := sha256.Sum256(data)
	putQ := control.VolumeFileQuery{Volume: "uploads", Path: pre + "today.db", Method: ActionPutVolumeFile, Size: int64(len(data)), MaxBytes: 1 << 20, Digest: sum, Overwrite: true}

	// No grant: bob has no plan; a bad query is Invalid.
	_, err := bob.VolumeFilePlan(ctx, "shop", putQ)
	wantCode(t, err, CodeDenied)
	bad := putQ
	bad.Digest = [32]byte{}
	_, err = alice.VolumeFilePlan(ctx, "shop", bad)
	wantCode(t, err, CodeInvalid)

	// Expected of a grant: the catalog revision, TenantMembers' Collection.
	cat := func(c Conn, tenant string) uint64 {
		t.Helper()
		p, err := c.TenantMembers(ctx, tenant, "")
		if err != nil || p.Collection == 0 {
			t.Fatalf("tenant-members %+v %v", p, err)
		}
		return p.Collection
	}
	grant := access.VolumeFileFolderGrant{Tenant: "shop", Volume: "uploads", Prefix: pre, User: "u-bob"}
	if _, res := submit(t, alice, ActionGrantVolumeFiles, cat(alice, "shop")-1, grant, rootFor(t, alice, ActionGrantVolumeFiles)); res.Code != ResultConditionFailed {
		t.Fatalf("grant with an old Expected %+v", res)
	}
	if _, res := submit(t, alice, ActionGrantVolumeFiles, cat(alice, "shop"), grant, rootFor(t, alice, ActionGrantVolumeFiles)); res.Code != ResultApplied {
		t.Fatalf("grant %+v", res)
	}
	if _, res := submit(t, alice, ActionGrantVolumeFiles, cat(alice, "shop"), grant, rootFor(t, alice, ActionGrantVolumeFiles)); res.Code != ResultApplied {
		t.Fatalf("grant again %+v", res)
	}
	if rows, err := fc(alice).volumeFileGrants(ctx, "shop", "uploads"); err != nil || len(rows) != 1 || rows[0].App != "" {
		t.Fatalf("grants %+v %v", rows, err)
	}
	// sfcd: the grantee needs tenant Read (bob is not in payments).
	admin := passwordLogin(t, f, "admin", "admin")
	pg := access.VolumeFileFolderGrant{Tenant: "payments", Volume: "ledger-data", Prefix: pre, User: "u-bob"}
	if _, res := submit(t, admin, ActionGrantVolumeFiles, cat(admin, "payments"), pg, rootFor(t, admin, ActionGrantVolumeFiles)); res.Code != ResultForbidden {
		t.Fatalf("grant to a non-member %+v", res)
	}
	other := putQ
	other.Path = "other/x.db"
	_, err = bob.VolumeFilePlan(ctx, "shop", other)
	wantCode(t, err, CodeDenied)

	// put: plan carries the change; Expected is the volume revision.
	p, _ := bob.VolumeFilePlan(ctx, "shop", putQ)
	if p.Change.Scope.Tenant != "shop" || p.Change.Scope.ID != "uploads" || p.Change.Digest != sum || p.Revision == 0 {
		t.Fatalf("plan %+v", p)
	}
	if _, res := submit(t, bob, ActionPutVolumeFile, p.Revision-1, p.Change, rootFor(t, bob, ActionPutVolumeFile)); res.Code != ResultConditionFailed {
		t.Fatalf("old Expected %v", res.Code)
	}
	op, res := reserve(bob, putQ)
	if res.Code != ResultApplied {
		t.Fatalf("reserve put %v", res.Code)
	}
	id, err := VolumeFileID(op)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := bob.VolumeFileStatus(ctx, "shop", id); err != nil || v.Phase != "Reserved" || v.Method != ActionPutVolumeFile {
		t.Fatalf("status %+v %v", v, err)
	}
	// A second writer waits for the first.
	if _, res := reserve(alice, control.VolumeFileQuery{Volume: "uploads", Path: pre + "today.db", Method: ActionDeleteVolumeFile}); res.Code != ResultConditionFailed {
		t.Fatalf("second writer %v", res.Code)
	}
	// Recover before any I/O: Unknown, the job stays Reserved.
	_, err = bob.VolumeFile(ctx, op, nil, nil)
	wantCode(t, err, CodeUnknown)
	// The reply is lost after the I/O: Unknown, then recover by source nil.
	f.LoseNextReply("volume-file", true)
	_, err = bob.VolumeFile(ctx, op, bytes.NewReader(data), nil)
	wantCode(t, err, CodeUnknown)
	if v, err := bob.VolumeFileStatus(ctx, "shop", id); err != nil || v.Phase != "Completed" || v.Code != "ok" || v.Result == nil || v.Result.Digest != sum {
		t.Fatalf("status after loss %+v %v", v, err)
	}
	if r, err := bob.VolumeFile(ctx, op, nil, nil); err != nil || r.Code != "ok" || r.Result.Size != int64(len(data)) || r.ID != id {
		t.Fatalf("recover %+v %v", r, err)
	}

	// Lost before the I/O: Reserved; resume streams it once.
	putQ2 := putQ
	putQ2.Path = pre + "yesterday.db"
	op2, _ := reserve(bob, putQ2)
	f.LoseNextReply("volume-file", false)
	_, err = bob.VolumeFile(ctx, op2, bytes.NewReader(data), nil)
	wantCode(t, err, CodeUnknown)
	id2, _ := VolumeFileID(op2)
	if v, _ := bob.VolumeFileStatus(ctx, "shop", id2); v.Phase != "Reserved" {
		t.Fatalf("lost before I/O %+v", v)
	}
	if r, err := bob.VolumeFile(ctx, op2, bytes.NewReader(data), nil); err != nil || r.Code != "ok" {
		t.Fatalf("resume %+v %v", r, err)
	}

	// A wrong body, or no overwrite over a file: the job completes with a code.
	putQ3 := putQ
	putQ3.Overwrite = false
	op3, _ := reserve(bob, putQ3)
	if r, err := bob.VolumeFile(ctx, op3, bytes.NewReader(data), nil); err != nil || r.Code != "conflict" || r.Result != nil {
		t.Fatalf("no overwrite %+v %v", r, err)
	}
	putQ4 := putQ
	putQ4.Path = pre + "bad.db"
	op4, _ := reserve(bob, putQ4)
	if r, _ := bob.VolumeFile(ctx, op4, bytes.NewReader([]byte("other")), nil); r.Code != "invalid" {
		t.Fatalf("wrong body %+v", r)
	}

	// get: the result's Size and Digest let the caller check before it publishes.
	opG, _ := reserve(bob, control.VolumeFileQuery{Volume: "uploads", Path: pre + "today.db", Method: ActionGetVolumeFile, MaxBytes: 1 << 20})
	var out bytes.Buffer
	if r, err := bob.VolumeFile(ctx, opG, nil, &out); err != nil || r.Code != "ok" || !bytes.Equal(out.Bytes(), data) || r.Result.Digest != sha256.Sum256(out.Bytes()) {
		t.Fatalf("get %+v %v", r, err)
	}
	opG2, _ := reserve(bob, control.VolumeFileQuery{Volume: "uploads", Path: pre + "today.db", Method: ActionGetVolumeFile, MaxBytes: 4})
	if r, _ := bob.VolumeFile(ctx, opG2, nil, &out); r.Code != "limit" {
		t.Fatalf("get over MaxBytes %+v", r)
	}
	opG3, _ := reserve(bob, control.VolumeFileQuery{Volume: "uploads", Path: pre + "none.db", Method: ActionGetVolumeFile, MaxBytes: 4})
	if r, _ := bob.VolumeFile(ctx, opG3, nil, &out); r.Code != "not-found" {
		t.Fatalf("get missing %+v", r)
	}

	// list: 64 entries a page, Next is the After of the next page.
	for i := range 64 {
		q := putQ
		q.Path = fmt.Sprintf("%sold-%02d.db", pre, i)
		o, _ := reserve(alice, q)
		if r, err := alice.VolumeFile(ctx, o, bytes.NewReader(data), nil); err != nil || r.Code != "ok" {
			t.Fatalf("seed %d %+v %v", i, r, err)
		}
	}
	list := func(after string) ([]string, string) {
		t.Helper()
		o, res := reserve(bob, control.VolumeFileQuery{Volume: "uploads", Path: pre, Method: ActionListVolumeFiles, After: after})
		if res.Code != ResultApplied {
			t.Fatalf("list %v", res.Code)
		}
		r, err := bob.VolumeFile(ctx, o, nil, nil)
		if err != nil || r.Code != "ok" {
			t.Fatalf("list %+v %v", r, err)
		}
		var paths []string
		for _, e := range r.Entries {
			paths = append(paths, e.Path)
		}
		return paths, r.Next
	}
	page, next := list("")
	if len(page) != 64 || next != page[63] {
		t.Fatalf("page 1 %d %q", len(page), next)
	}
	page, next = list(next)
	if len(page) != 2 || next != "" || page[1] != pre+"yesterday.db" {
		t.Fatalf("page 2 %v %q", page, next)
	}

	// delete, then the job of another user is not bob's.
	opD, _ := reserve(bob, control.VolumeFileQuery{Volume: "uploads", Path: pre + "today.db", Method: ActionDeleteVolumeFile})
	if r, err := bob.VolumeFile(ctx, opD, nil, nil); err != nil || r.Code != "ok" {
		t.Fatalf("delete %+v %v", r, err)
	}
	_, err = alice.VolumeFile(ctx, opD, nil, nil)
	if err == nil {
		t.Fatal("another user's job")
	}
	idD, _ := VolumeFileID(opD)
	if v, err := alice.VolumeFileStatus(ctx, "shop", idD); err != nil || v.Code != "ok" {
		t.Fatalf("manager reads status %+v %v", v, err)
	}

	// Revoke: no plan for bob; revoking again is Invalid.
	if _, res := submit(t, alice, ActionRevokeVolumeFileGrant, cat(alice, "shop"), grant, rootFor(t, alice, ActionRevokeVolumeFileGrant)); res.Code != ResultApplied {
		t.Fatalf("revoke %+v", res)
	}
	if _, res := submit(t, alice, ActionRevokeVolumeFileGrant, cat(alice, "shop"), grant, rootFor(t, alice, ActionRevokeVolumeFileGrant)); res.Code != ResultInvalid {
		t.Fatalf("revoke again %+v", res)
	}
	_, err = bob.VolumeFilePlan(ctx, "shop", putQ)
	wantCode(t, err, CodeDenied)
	_, err = bob.VolumeFileStatus(ctx, "payments", id)
	wantCode(t, err, CodeDenied)
}
