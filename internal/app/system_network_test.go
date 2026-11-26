// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/tenancy"
)

func TestSystemNetworkStepFollowsNodeAppsAndWorkRole(t *testing.T) {
	n, err := tenancy.New([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		want, work bool
		step       string
	}{
		{false, true, ""},
		{true, true, "use"},
		{true, false, ""}, // only a work server starts using it
	} {
		if got, _ := systemNetworkStep(n, nil, "node-a", c.want, c.work); got != c.step {
			t.Fatalf("unused, want=%v work=%v: %q", c.want, c.work, got)
		}
	}
	used, err := n.SetSystemUse("node-b", true)
	if err != nil {
		t.Fatal(err)
	}
	// node-b uses it but it has no members: any work server joins (and so
	// makes it); a server that is not a work server does not.
	if got, _ := systemNetworkStep(used, []string{"node-b"}, "node-a", false, true); got != "join" {
		t.Fatalf("join: %q", got)
	}
	if got, _ := systemNetworkStep(used, []string{"node-b"}, "node-a", false, false); got != "" {
		t.Fatalf("not a work server: %q", got)
	}
	// node-b left the cluster without saying it stopped: nobody joins
	if got, _ := systemNetworkStep(used, nil, "node-a", false, true); got != "" {
		t.Fatalf("removed user: %q", got)
	}
	// node-b stops while it is not a work server any more
	if got, _ := systemNetworkStep(used, []string{"node-b"}, "node-b", false, false); got != "use" {
		t.Fatalf("off: %q", got)
	}
}
