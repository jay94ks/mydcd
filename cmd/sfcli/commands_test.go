// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewCommandsRouteBeforeOldFlags(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var out, diagnostic bytes.Buffer
	if code := run([]string{"op", "list", "-o", "json"}, &out, &diagnostic); code != 0 || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("code %d out %q err %q", code, out.String(), diagnostic.String())
	}
	out.Reset()
	if code := run([]string{"op", "show", "nope"}, &out, &diagnostic); code != 1 || !strings.Contains(diagnostic.String(), "no such operation") {
		t.Fatalf("code %d err %q", code, diagnostic.String())
	}
}
