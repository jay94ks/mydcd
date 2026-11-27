// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
)

// validID reports whether s is a lower-case name: a letter, then letters,
// digits or '-', at most 63 bytes.
func validID(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

var replacedFields = map[string][]string{
	"put-registry":          {"Spec"},
	"put-external-registry": {"Spec"},
	"vault-move":            {"Parent"}, "vault-approval-age": {"Seconds"},
	"set-volume-capacity":     {"Bytes"},
	"set-lifecycle-policy":    {"Enabled", "Build", "Execution", "Resolver", "CompiledCacheBytes"},
	"reconfigure-tun-network": {"Target"},
}

// explicitFields reports whether a replacement action names every field it
// replaces. Setting a list/ACL is an explicit replacement, never an
// omitted-field patch, so a missing field cannot clear policy.
func explicitFields(action string, raw []byte) bool {
	required, ok := replacedFields[action]
	if !ok {
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, key := range required {
		if len(fields[key]) == 0 || bytes.Equal(fields[key], []byte("null")) {
			return false
		}
	}
	if action == "put-registry" || action == "put-external-registry" {
		var spec map[string]json.RawMessage
		if json.Unmarshal(fields["Spec"], &spec) != nil || len(spec["Enabled"]) == 0 || bytes.Equal(spec["Enabled"], []byte("null")) {
			return false
		}
	}
	if action == "reconfigure-tun-network" {
		var target map[string]json.RawMessage
		if json.Unmarshal(fields["Target"], &target) != nil || len(target["Members"]) == 0 || bytes.Equal(target["Members"], []byte("null")) {
			return false
		}
	}
	return true
}
