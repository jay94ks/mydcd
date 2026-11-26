// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func storageItem(t *testing.T, f *fixture, path, id string) map[string]any {
	t.Helper()
	code, out := f.do("GET", path, nil)
	if code != 200 {
		t.Fatalf("list %s: %d %v", path, code, out)
	}
	for _, it := range out["items"].([]any) {
		if m := it.(map[string]any); m["id"] == id {
			return m
		}
	}
	return nil
}

func limitItem(t *testing.T, f *fixture, tenant, node string) map[string]any {
	t.Helper()
	code, out := f.do("GET", "/api/v1/t/"+tenant+"/resources", nil)
	if code != 200 {
		t.Fatalf("resources: %d %v", code, out)
	}
	for _, it := range out["items"].([]any) {
		if l, ok := it.(map[string]any)["limit"].(map[string]any); ok && l["node"] == node {
			return l
		}
	}
	return nil
}

// userPayload decodes the signed change payload of user's stored op.
func userPayload(t *testing.T, f *fixture, user, opID string, v any) {
	t.Helper()
	o, err := f.store.GetOp(user, opID)
	if err != nil {
		t.Fatal(err)
	}
	op, err := mydc.DecodeOperation(o.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(op.Change.Payload, v); err != nil {
		t.Fatal(err)
	}
}
