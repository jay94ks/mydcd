// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"
)

func TestAppSourceCLISeparatesRawDocumentFromVersionPages(t *testing.T) {
	o, err := parseAppSourceOptions("app-source", []string{"--app", "store", "--deployment", "deploy", "--revision", "2", "--raw"}, io.Discard)
	if err != nil || !o.raw || o.selection.Revision != 2 || o.selection.App != "store" || o.selection.Deployment != "deploy" {
		t.Fatal("raw retained app document", o, err)
	}
	o, err = parseAppSourceOptions("app-revisions", []string{"--app", "store", "--after", "cursor"}, io.Discard)
	if err != nil || o.raw || o.after != "cursor" {
		t.Fatal("retained versions", err)
	}
	o, err = parseAppSourceOptions("app-source", []string{"--app", "store", "--revision", "2", "--section", "local-services", "--raw"}, io.Discard)
	if err != nil || !o.raw || o.selection.Section != "local-services" || o.selection.Revision != 2 {
		t.Fatal("separate accepted local YAML selector", o, err)
	}
	for _, args := range [][]string{{}, {"--app", "../other"}, {"--app", "one", "--app", "two"}, {"--app", "store", "--revision", "0"}, {"--app", "store", "--revision", "-1"}, {"--app", "store", "--section", "unknown"}, {"--app", "store", "--after", "cursor"}} {
		if _, err := parseAppSourceOptions("app-source", args, io.Discard); err == nil {
			t.Fatal("unsafe source syntax accepted", args)
		}
	}
	if _, err := parseAppSourceOptions("app-revisions", []string{"--app", "store", "--raw"}, io.Discard); err == nil {
		t.Fatal("version page accepted source-only options")
	}
}
