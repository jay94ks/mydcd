// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkSystemCommands(t *testing.T) {
	f := newCLIFixture(t)
	var v systemNetworkView
	f.json(&v, "network", "system", "show")
	if v.Range != "10.254.0.0/16" || v.Servers != "10.254.240.0/20" || len(v.Users) != 0 || len(v.Members) != 0 {
		t.Fatalf("%+v", v)
	}
	if out := f.run(0, "network", "system", "show"); !strings.Contains(out, "Range: 10.254.0.0/16") || !strings.Contains(out, "Server addresses: 10.254.240.0/20") || !strings.Contains(out, "Used by: (none)") {
		t.Fatal(out)
	}
	// the range is fixed
	f.run(2, "network", "system", "set-range", "10.20.0.0/19")
	// a workspace network may not take the system range
	f.run(0, "tenant", "create", "shop", "--nodes", "node-a")
	f.run(0, "node", "quota", "set", "node-a", "--cpu", "4", "--memory", "8GiB", "--networks", "8", "--consumers", "16")
	f.run(0, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1", "--memory", "1GiB")
	file := filepath.Join(f.home, "network.yaml")
	if err := os.WriteFile(file, []byte(strings.ReplaceAll(testNetwork, "10.240.", "10.254.")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, out := f.runBoth(1, "--tenant", "shop", "network", "create", "-f", file); !strings.Contains(out, "overlaps the system network range 10.254.0.0/16") {
		t.Fatal(out)
	}
}
