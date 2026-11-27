// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecoverNeedsVotersAndRequestID(t *testing.T) {
	var out, diag bytes.Buffer
	if code := run([]string{"recover", "--voters", "node-a"}, &out, &diag); code != 2 || !strings.Contains(diag.String(), "--request-id") {
		t.Fatal(code, diag.String())
	}
	diag.Reset()
	if code := run([]string{"--check-config", "recover"}, &out, &diag); code != 2 {
		t.Fatal(code, diag.String())
	}
}

func TestRestoreNeedsBackupKeyAndRequestID(t *testing.T) {
	var out, diag bytes.Buffer
	if code := run([]string{"restore", "--config", "node.yaml", "--request-id", "restore-1"}, &out, &diag); code != 2 || !strings.Contains(diag.String(), "--backup") {
		t.Fatal(code, diag.String())
	}
	diag.Reset()
	if code := run([]string{"restore", "--config", "node.yaml", "--backup", "x.sfcbak", "--request-id", "restore-1"}, &out, &diag); code != 2 || !strings.Contains(diag.String(), "--backup-key-file") {
		t.Fatal(code, diag.String())
	}
	diag.Reset()
	if code := run([]string{"--check-config", "restore"}, &out, &diag); code != 2 {
		t.Fatal(code, diag.String())
	}
}
