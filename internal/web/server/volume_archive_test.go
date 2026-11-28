// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

// 보관 then 되살리기 of an app data store, followed through the volume row
// and the detail's archive list; the fake stands in for the owner node.
func TestVolumeArchiveAndRestore(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	base := "/api/v1/t/shop/volumes/sessions"
	detail := func() map[string]any {
		t.Helper()
		code, out := f.do("GET", base, nil)
		if code != 200 {
			t.Fatalf("detail: %d %v", code, out)
		}
		return out
	}
	if d := detail(); d["archiveReady"] != true || len(d["archives"].([]any)) != 0 {
		t.Fatalf("before: %v", d)
	}
	// Only app data stores.
	if code, out := f.do("POST", "/api/v1/t/shop/volumes/uploads/archive", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-000000000001"}); code != 409 || errCode(out) != "no-app" {
		t.Fatalf("tenant store: %d %v", code, out)
	}
	if code, out := f.do("POST", base+"/archive", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-000000000002", "id": "Bad"}); code != 422 {
		t.Fatalf("bad id: %d %v", code, out)
	}
	code, out := f.do("POST", base+"/archive", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-000000000003", "id": "nightly", "compress": false})
	if code != 202 && code != 200 || out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("archive: %d %v", code, out)
	}
	d := detail()
	v := d["volume"].(map[string]any)
	a := d["archives"].([]any)[0].(map[string]any)
	if v["phase"] != "Archived" || v["archiveID"] != "nightly" || a["phase"] != "Packing" || a["compression"] != "none" || a["store"] != "default" || a["maxBytes"].(float64) != 2<<30 {
		t.Fatalf("packing: %v %v", v, a)
	}
	// Restoring needs it Archived first.
	if code, out := f.do("POST", base+"/unarchive", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-000000000004"}); code == 200 && out["op"].(map[string]any)["state"] == "applied" {
		t.Fatalf("unarchive while packing: %d %v", code, out)
	}
	if err := fake.FinishVolumeArchive("shop", "php-shop", "sessions", ""); err != nil {
		t.Fatal(err)
	}
	if a := detail()["archives"].([]any)[0].(map[string]any); a["phase"] != "Archived" || a["dataBytes"] == nil {
		t.Fatalf("archived: %v", a)
	}
	code, out = f.do("POST", base+"/unarchive", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-000000000005"})
	if code != 202 && code != 200 || out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("unarchive: %d %v", code, out)
	}
	// A failed restore keeps the package and the volume archived.
	if err := fake.FinishVolumeArchive("shop", "php-shop", "sessions", "package-damaged"); err != nil {
		t.Fatal(err)
	}
	if a := detail()["archives"].([]any)[0].(map[string]any); a["phase"] != "Archived" || a["failure"] != "package-damaged" {
		t.Fatalf("unrestored: %v", a)
	}
	f.do("POST", base+"/unarchive", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-000000000006"})
	if err := fake.FinishVolumeArchive("shop", "php-shop", "sessions", ""); err != nil {
		t.Fatal(err)
	}
	d = detail()
	if v, a := d["volume"].(map[string]any), d["archives"].([]any)[0].(map[string]any); v["phase"] != "Ready" || v["archiveID"] != nil || a["phase"] != "Restored" {
		t.Fatalf("restored: %v %v", v, a)
	}
}

// 보관 is refused before both recipient keys are set; cancel and discard
// follow the archive's own revision.
func TestVolumeArchiveKeysCancelDiscard(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	base := "/api/v1/t/shop/volumes/sessions"
	fake.SetVolumeArchiveKeys([32]byte{1}, [32]byte{})
	if code, out := f.do("POST", base+"/archive", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000001"}); code != 409 || errCode(out) != "archive-keys" {
		t.Fatalf("no admin key: %d %v", code, out)
	}
	fake.SetVolumeArchiveKeys([32]byte{1}, [32]byte{2})
	f.do("POST", base+"/archive", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000002", "id": "one"})
	if code, out := f.do("POST", base+"/archives/one/cancel", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000003"}); out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("cancel: %d %v", code, out)
	}
	if err := fake.FinishVolumeArchive("shop", "php-shop", "sessions", ""); err != nil {
		t.Fatal(err)
	}
	f.do("POST", base+"/archive", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000004", "id": "two"})
	if err := fake.FinishVolumeArchive("shop", "php-shop", "sessions", ""); err != nil {
		t.Fatal(err)
	}
	if code, out := f.do("DELETE", base+"/archives/two", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000005"}); out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("discard: %d %v", code, out)
	}
	if code, out := f.do("DELETE", base+"/archives/none", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000006"}); code != 404 {
		t.Fatalf("missing archive: %d %v", code, out)
	}
	if err := fake.FinishVolumeArchive("shop", "php-shop", "sessions", ""); err != nil {
		t.Fatal(err)
	}
	_, out := f.do("GET", base, nil)
	archives := out["archives"].([]any)
	if len(archives) != 1 || archives[0].(map[string]any)["phase"] != "Discarded" || out["volume"].(map[string]any)["phase"] != "Ready" {
		t.Fatalf("after discard (the cancelled record is dropped by the next archive): %v", out)
	}
}
