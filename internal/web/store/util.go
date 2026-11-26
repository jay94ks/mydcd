// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"sort"
)

func hasPrefix(k, p []byte) bool { return bytes.HasPrefix(k, p) }

func lastPart(k []byte) string {
	i := bytes.LastIndexByte(k, 0)
	return string(k[i+1:])
}

func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }

func sortOpsNewest(ops []*Op) {
	sort.SliceStable(ops, func(i, j int) bool {
		if ops[i].SubmittedAt.Equal(ops[j].SubmittedAt) {
			return ops[i].ID > ops[j].ID
		}
		return ops[i].SubmittedAt.After(ops[j].SubmittedAt)
	})
}
