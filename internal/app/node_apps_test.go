// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/config"
)

func TestEnabledNodeAppIsRefusedUntilItsOwnerExists(t *testing.T) {
	var c config.Node
	if CheckNodeApps(c) != nil {
		t.Fatal("no node app refused")
	}
	c.NodeApps.Web = &config.NodeAppWeb{Enabled: true}
	if CheckNodeApps(c) == nil {
		t.Fatal("enabled web accepted without an owner")
	}
	if _, err := Open(c); err == nil {
		t.Fatal("runtime opened with an enabled node app")
	}
}
