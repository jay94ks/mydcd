// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"testing"

	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestNodeShellClosedDisplayUsesOnlyValidatedEndActor(t *testing.T) {
	end := sfcp.NodeShellEnd{Code: 0, Reason: "policy", ClosedBy: &sfcp.NodeShellActor{User: "bob", Username: "bob"}}
	if !end.Valid() {
		t.Fatal("valid end")
	}
	var out bytes.Buffer
	if _, err := fmtNodeShellClosed(&out, &end); err != nil || !bytes.Contains(out.Bytes(), []byte("policy by bob (bob)")) {
		t.Fatal("signed close actor missing", err)
	}
}
