// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
)

type appliedDriver struct{}

func (appliedDriver) Execute(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}
func (appliedDriver) Recover(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}

// Only the container the journal holds, with its fixed address, may join
// the system bridge; a container that is not a cluster app's is not ours.
func TestJoiningAdmitsOnlyTheJournaledContainerAtItsAddress(t *testing.T) {
	j, err := reconcile.OpenJournal(filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	o := &Owner{journal: j, driver: &driver{engine: &engine.Client{Owner: "node-a"}}}
	spec := ContainerSpec{Schema: 1, App: Web, Image: "sha256:aa", Digest: "sha256:bb", Bridge: "bridge/sys", BridgeGeneration: 1, Address: netip.MustParseAddr("10.254.7.2"), User: "10001", Cmd: []string{"/web"}}
	raw, _ := json.Marshal(spec)
	key := journalKey(Web)
	res := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	if err = j.Desired(key, reconcile.Desired{Revision: 1, Resource: res}, 1); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), key, appliedDriver{}); err != nil {
		t.Fatal(err)
	}
	_, id, err := o.driver.parameters(key, res)
	if err != nil {
		t.Fatal(err)
	}
	at := []netip.Prefix{netip.MustParsePrefix("10.254.7.2/24")}
	if handled, allow := o.Joining("/"+id.Name, id.Labels, at); !handled || !allow {
		t.Fatal("journaled container refused", handled, allow)
	}
	if handled, allow := o.Joining(id.Name, id.Labels, []netip.Prefix{netip.MustParsePrefix("10.254.7.9/24")}); !handled || allow {
		t.Fatal("other address admitted")
	}
	stale := map[string]string{}
	for k, v := range id.Labels {
		stale[k] = v
	}
	stale["org.sfc.generation"] = "2"
	if handled, allow := o.Joining(id.Name, stale, at); !handled || allow {
		t.Fatal("other generation admitted")
	}
	if handled, allow := o.Joining("sfc-cluster-app-web", map[string]string{}, at); !handled || allow {
		t.Fatal("unlabeled cluster-app name admitted")
	}
	if handled, _ := o.Joining("sfc-container-1234", map[string]string{"org.sfc.kind": "container"}, at); handled {
		t.Fatal("workload container taken as a cluster app")
	}
	if handled, allow := (*Owner)(nil).Joining(id.Name, id.Labels, at); !handled || allow {
		t.Fatal("no owner must refuse a cluster app")
	}
}
