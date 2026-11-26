// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// Called by the existing interpreted/compiled checker fixture after its real
// health witness, original down and explicit tenant script retire/delete.
// The existing mixed fixture compiles an inline endpoint; its named native-file
// remains interpreted. Thus this helper proves app-binding rows, not a live
// compiler row. Active named build-job rows use the shared-control core test.
func verifyManagedLifecyclePublicReads(t *testing.T, ctx context.Context, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, live, retired, deleted bool) {
	t.Helper()
	query := control.PublicReadQuery{Name: "native-file"}
	page := readNativePublicPage(t, ctx, user, peer, session, "lifecycle-uses", "tenant", query)
	cli := nativePublicCLI(t, ctx, root, "lifecycle-uses", "tenant", query)
	book, err := p.Lifecycles(read().State)
	if err != nil {
		t.Fatal(err)
	}
	registered, ok := book.Script("tenant", query.Name)
	if !ok || len(registered.Versions) != 1 || registered.Versions[0].Revision != 1 || registered.Versions[0].Active != !retired || registered.Versions[0].Deleted != deleted {
		t.Fatal("public read boundary is not the original script lifetime", registered)
	}
	wantRevision := uint64(1)
	if retired {
		wantRevision++
	}
	if deleted {
		wantRevision++
	}
	if registered.Revision != wantRevision {
		t.Fatal("retire/delete changed immutable source revision or lost CAS floor", registered)
	}
	want := 0
	if live {
		want = 1
	}
	if page.Total != want || len(page.Rows) != want || cli.Total != want || !reflect.DeepEqual(page.Rows, cli.Rows) {
		t.Fatal("actual User/CLI original checker references disagree", live, retired, deleted, page, cli)
	}
	var uses []checker.Use
	for _, use := range book.Uses() {
		if use.Tenant == "tenant" && slices.Contains(use.Scripts, checker.NamedReference{Name: query.Name, Revision: 1}) {
			uses = append(uses, use)
		}
	}
	if len(uses) != want {
		t.Fatal("public script rows differ from original deletion fence", uses, page)
	}
	if live {
		apps, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		task := deployment.ResourceKey("task", "tenant", "app", "web")
		object := read().State.Object(task)
		binding, ok := apps.Binding(deployment.ObjectRef{Key: task, Generation: object.Generation, Revision: object.Revision})
		parent, bound := control.CheckerBindingUse(binding)
		row := page.Rows[0].Lifecycle
		if !ok || !bound || parent.Digest() != uses[0].Digest() || row == nil || row.ID != parent.ID || row.Kind != "app-binding" || row.App != "app" || row.Service != "web" || row.Node != "node-a" || row.Revision != 1 || row.Standalone != "" {
			t.Fatal("public checker use is not the actual original accepted Task Binding", row, ok, bound)
		}
		// No build-job row is claimed after Healthy: every original compiler
		// job has closed, and its evidence remains independently retained.
		for _, job := range book.BuildJobs() {
			if job.Phase != "closed" || job.Closure == nil {
				t.Fatal("checker read was taken before original compiler closure", job.Phase)
			}
		}
	}
	raw, err := json.Marshal(page.Rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"Signature", "Parent", "Owner", "Source", "Manifest", "Closure", "Password", "Environment"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private checker source/capability leaked in public use rows", private)
		}
	}
}
