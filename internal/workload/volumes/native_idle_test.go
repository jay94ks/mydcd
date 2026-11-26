// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

func TestNativeIdleRequiresOriginalJournalNoPinAndPositiveEngineQuery(t *testing.T) {
	ctx := context.Background()
	spec := nativeTestSpec(t)
	f := nativeSDK(t, spec)
	setContainers := func(status int, items string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.containerHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Error("Idle attempted a native mutation", r.Method)
			}
			var filters map[string]map[string]bool
			all := r.URL.Query().Get("all")
			if json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters) != nil || len(filters["volume"]) != 1 || !filters["volume"][f.value.Name] || all != "1" && all != "true" {
				t.Error("Idle omitted stopped/unowned attachments or exact original native filter")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(items))
		})
	}
	setContainers(200, "[]")
	path := filepath.Join(t.TempDir(), "native.db")
	m, err := OpenNative(path, f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	key, err := m.Desired(spec, 1, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	ready, err := m.Ready(ctx, key, makeFixture(t).a)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.CheckIdle(ctx, ready); err != nil {
		t.Fatal("positive original native idle observation", err)
	}
	pin, err := m.Pin(ctx, key, "unknown-start", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.CheckIdle(ctx, ready); err == nil {
		t.Fatal("local pin treated as idle")
	}
	if err = m.Return(pin); err != nil {
		t.Fatal(err)
	}
	for _, response := range []struct {
		code int
		body string
	}{{200, `[{"Id":"stopped-original","State":"exited"}]`}, {500, `{"message":"owned injected query failure"}`}} {
		setContainers(response.code, response.body)
		if err = m.CheckIdle(ctx, ready); err == nil {
			t.Fatal("Engine attachment/query failure treated as idle")
		}
	}
	setContainers(200, "[]")
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenNative(path, f.client)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.CheckIdle(ctx, ready); err != nil || f.createCount() != 1 || f.deleteCount() != 0 {
		t.Fatal("Idle recovery changed the original native effect", err)
	}
	if err = m.DeleteDesired(key, 2, ready.Generation); err != nil {
		t.Fatal(err)
	}
	if err = m.CheckIdle(ctx, ready); err == nil {
		t.Fatal("changed original native goal treated as idle")
	}
	missing, err := OpenNative(filepath.Join(t.TempDir(), "unrecorded.db"), f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer missing.Close()
	if err = missing.CheckIdle(ctx, ready); err == nil {
		t.Fatal("missing original journal treated as idle")
	}
}
