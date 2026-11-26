// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Reuse the real service/native/Volume/Group fixture and its rollback. These
// additional reads do not submit a replacement app or synthesize owner facts.
func TestRQ10StandaloneResourceReadsAndOriginalRetirement(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppStandaloneServiceRecreation, true, false, true)
}

func verifyNativeStandaloneResourceReads(t *testing.T, ctx context.Context, user userauth.Client, peer mydcp.Peer, session access.Session, name, task string, live bool) {
	t.Helper()
	for _, method := range []string{"network-users", "volume-users", "image-trust", "vault-usages"} {
		q := control.PublicReadQuery{}
		switch method {
		case "network-users":
			q.Name = "shared-services"
		case "volume-users":
			q.Name = "data"
		case "vault-usages":
			q.Name = "group"
		}
		page := readNativePublicPage(t, ctx, user, peer, session, method, "tenant", q)
		found := 0
		for _, row := range page.Rows {
			if u := row.User; u != nil && u.Standalone == name {
				found++
				if u.Kind != "standalone" || u.App != "" || u.Task != task || u.Node != "node-a" || !u.Live || u.ContainerPresent == nil || !*u.ContainerPresent {
					t.Fatal("standalone public use lost actual Task/owner", method, u)
				}
				if method == "network-users" && (u.EndpointPresent == nil || !*u.EndpointPresent) {
					t.Fatal("standalone network use lacks inspected endpoint", u)
				}
			}
			if image := row.Image; image != nil && image.Standalone == name {
				found++
				if image.Kind != "standalone" || image.App != "" || image.Node != "node-a" || len(image.Rules) == 0 {
					t.Fatal("standalone image use lost its trust rule", image)
				}
			}
			if usage := row.SecretUsage; usage != nil && usage.Standalone == name {
				found++
				if usage.App != "" || usage.Node != "node-a" || !usage.Live || len(usage.Secrets) == 0 {
					t.Fatal("standalone Secret use lost original grant", usage)
				}
			}
		}
		if live && found == 0 || !live && found != 0 {
			t.Fatal("standalone public use differs from native retirement", method, live, found)
		}
	}
}
