// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRegistryArchiveHelp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{{"registry", "export", "--help"}, {"registry", "import", "--help"}} {
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "OCI") {
			t.Fatalf("sfcli %v: code %d: %s %s", args, code, out.String(), diagnostic.String())
		}
	}
}
