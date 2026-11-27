// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkBridgeCommands(t *testing.T) {
	f := newCLIFixture(t)
	f.run(0, "tenant", "create", "shop", "--nodes", "node-a")
	f.run(0, "node", "quota", "set", "node-a", "--cpu", "4", "--memory", "8GiB", "--networks", "8", "--consumers", "16")
	f.run(0, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1", "--memory", "1GiB")
	for _, text := range []string{testNetwork, strings.NewReplacer("shop-net", "shop-db", "10.240.", "10.241.", "shop.sfc.test", "db.sfc.test").Replace(testNetwork)} {
		file := filepath.Join(f.home, "network.yaml")
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		f.run(0, "--tenant", "shop", "network", "create", "-f", file)
	}
	f.run(2, "--tenant", "shop", "network", "bridge", "create", "link", "--network", "shop-net")
	f.run(2, "--tenant", "shop", "network", "bridge", "create", "link", "--network", "shop-net", "--to", "shop-db", "--ports", "80")
	f.run(2, "--tenant", "shop", "network", "bridge", "create", "link", "--network", "shop-net", "--to", "shop-db", "--direction", "up")
	f.run(0, "--tenant", "shop", "network", "bridge", "create", "link", "--network", "shop-net", "--to", "shop-db", "--direction", "out", "--protocol", "tcp", "--ports", "80,8000-8100")
	var list []bridgeView
	f.json(&list, "--tenant", "shop", "network", "bridge", "list")
	if len(list) != 1 || list[0].Owner != "shop" || list[0].Name != "link" || list[0].A != "shop/shop-net" || list[0].B != "shop/shop-db" || list[0].Direction != "a-to-b" || list[0].Protocol != "tcp" || list[0].Ports != "80,8000-8100" || list[0].State != "open" {
		t.Fatalf("%+v", list)
	}
	if _, out := f.runBoth(1, "--tenant", "shop", "network", "bridge", "create", "back", "--network", "shop-db", "--to", "shop-net"); !strings.Contains(out, "bridge-exists") {
		t.Fatal(out)
	}
	f.run(2, "--tenant", "shop", "network", "bridge", "approve", "link")
	f.run(1, "--tenant", "shop", "network", "bridge", "close", "nope")
	f.run(0, "--tenant", "shop", "network", "bridge", "close", "link")
	f.json(&list, "--tenant", "shop", "network", "bridge", "list")
	if len(list) == 1 && list[0].State != "closing" {
		t.Fatalf("%+v", list)
	}
}
