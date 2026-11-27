// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestPublicReadCLIRejectsCrossMethodFlagsBeforeWallet(t *testing.T) {
	for _, args := range [][]string{{"network-users", "--name", "services"}, {"route-endpoints"}} {
		if _, _, _, err := parsePublicRead(args, io.Discard); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"network-users"}, {"network-users", "--name", "services", "--node", "node-a"}, {"image-trust", "--name", "data"}, {"vault-usages", "--name", "group", "--app", "app"}, {"volume-users", "--name", "data", "--app", "app"}, {"volume-backup-limits"}, {"volume-file-grants"}} {
		if _, _, _, err := parsePublicRead(args, io.Discard); err == nil {
			t.Fatal("invalid syntax accepted", args)
		}
	}
}

func TestRQ10ManagementHelpKeepsTenantStorageAndPreviousCommands(t *testing.T) {
	var out bytes.Buffer
	if !userHelp([]string{"manage", "--help"}, &out) {
		t.Fatal("management help not dispatched")
	}
	for _, fragment := range []string{"tenant-storage", "lifecycle-uses"} {
		if !strings.Contains(out.String(), fragment) {
			t.Fatal("management command lost during integration", fragment)
		}
	}
	for _, command := range []string{"server-version", "service-call"} {
		out.Reset()
		if !userHelp([]string{command, "--help"}, &out) || !strings.Contains(out.String(), command) {
			t.Fatal("user command help lost", command)
		}
	}
}
