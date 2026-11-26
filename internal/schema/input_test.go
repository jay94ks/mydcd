// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"strings"
	"testing"
)

func TestMetadataInputRejectsAmbiguousOrUnboundedDocuments(t *testing.T) {
	type nested struct{ ID string }
	type document struct {
		Schema uint8  `json:"schema"`
		Target nested `json:"target"`
	}
	good, err := Input[document]([]byte(" {\n\"schema\":1, \"target\":{\"ID\":\"alpha\"}} "))
	if err != nil || good.Schema != 1 || good.Target.ID != "alpha" {
		t.Fatal("human whitespace or exact typed field rejected", err)
	}
	bad := []string{
		`{"schema":1,"schema":2}`, `{"schema":1,"schem\u0061":2}`,
		`{"Schema":1}`, `{"schema":1,"target":{"id":"alpha"}}`,
		`{"schema":1,"target":{"ID":"alpha","password":"private"}}`,
		`{"schema":256}`, `{"schema":1} {}`, `{"schema":1} trailing`,
		`{"schema":1,"target":{"ID":"alpha","ID":"beta"}}`,
		strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34),
		`{"schema":1,"target":{"ID":"` + strings.Repeat("x", 32<<10) + `"}}`,
		string([]byte{'{', '"', 255, '"', ':', '1', '}'}),
	}
	for i, raw := range bad {
		if _, err := Input[document]([]byte(raw)); err != ErrInput {
			t.Fatalf("unsafe input %d accepted: %v", i, err)
		}
	}
}
