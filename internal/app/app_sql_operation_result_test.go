// SPDX-License-Identifier: Apache-2.0

package app

import (
	"maps"
	"net/http"
	"strings"
	"testing"
)

// This is the sample application's result contract, not a Seafield Cluster acknowledgement
// or a substitute for a successful original HTTP response. Only POST/PUT return
// a committed original value through the sample's read-only operation endpoint.
func originalSQLWriteResult(method, key, operation, value string, saved map[string]any) bool {
	if method != http.MethodPost && method != http.MethodPut || key == "" || operation == "" {
		return false
	}
	id, idOK := saved["id"].(string)
	op, opOK := saved["operation"].(string)
	got, valueOK := saved["value"].(string)
	return idOK && opOK && valueOK && id == key && op == operation && got == value && saved["error"] == nil
}

func TestOriginalSQLWriteResultRequiresExactOriginal(t *testing.T) {
	value := strings.Repeat("M", 128<<10)
	original := map[string]any{"id": "row", "operation": "write-one", "value": value}
	for _, name := range []string{"post", "put", "empty-value", "wrong-id", "wrong-operation", "same-length-other-value", "missing-value", "wrong-type", "known-error", "read", "delete", "missing-key", "missing-operation"} {
		t.Run(name, func(t *testing.T) {
			method, key, op, payload := http.MethodPost, "row", "write-one", value
			saved := maps.Clone(original)
			want := false
			switch name {
			case "post":
				want = true
			case "put":
				method, want = http.MethodPut, true
			case "empty-value":
				payload, saved["value"], want = "", "", true
			case "wrong-id":
				saved["id"] = "other"
			case "wrong-operation":
				saved["operation"] = "other"
			case "same-length-other-value":
				saved["value"] = strings.Repeat("N", len(value))
			case "missing-value":
				delete(saved, "value")
			case "wrong-type":
				saved["value"] = 131072
			case "known-error":
				saved["error"] = "conflict"
			case "read":
				method = http.MethodGet
			case "delete":
				method = http.MethodDelete
			case "missing-key":
				key = ""
			case "missing-operation":
				op = ""
			}
			if originalSQLWriteResult(method, key, op, payload, saved) != want {
				t.Fatal("unsettled original write was accepted or exact result rejected", name)
			}
		})
	}
}
