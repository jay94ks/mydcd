// SPDX-License-Identifier: Apache-2.0

package userauth

import "testing"

// A reply from a newer sfcd of the same major may carry fields this build
// does not know; it is read and they are skipped. Requests stay strict.
func TestRepliesSkipUnknownFields(t *testing.T) {
	raw := []byte(`{"Schema":1,"Code":"ok","FromANewerBuild":{"x":1},"RaftStatus":{"Leader":"a","Nodes":[{"Node":"a","NewColumn":2}]}}`)
	var r Reply
	if err := lenient(raw, &r); err != nil || r.Code != "ok" || r.RaftStatus == nil || r.RaftStatus.Leader != "a" || len(r.RaftStatus.Nodes) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if strict(raw, &Reply{}) == nil {
		t.Fatal("strict accepted unknown fields")
	}
	for _, bad := range []string{``, `{"Schema":1}{}`, `{"Schema":`, `[]`} {
		if lenient([]byte(bad), &Reply{}) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
