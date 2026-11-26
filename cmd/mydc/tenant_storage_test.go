// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestTenantStorageCLIKeepsSystemAndTenantPathsSeparate(t *testing.T) {
	for _, args := range [][]string{{}, {"--node", "node-b"}, {"--node", "node-b", "--after", "snapshot:node-b/ssd"}} {
		if _, err := parseTenantStorageOptions(args, io.Discard); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"--node", "../node"}, {"--node", "node-a", "--node", "node-b"}, {"--tenant", "foreign"}, {"unexpected"}} {
		if _, err := parseTenantStorageOptions(args, io.Discard); err == nil {
			t.Fatal("invalid tenant root command accepted", args)
		}
	}
	var out, diagnostic bytes.Buffer
	code := runTenantStorageQuery(context.Background(), nil, userauth.Client{}, mydcp.Peer{}, userauth.Stored{}.Session, "", &out, &diagnostic)
	if code != 2 || out.Len() != 0 {
		t.Fatal("missing explicit tenant reached transport", code, out.String())
	}
}
