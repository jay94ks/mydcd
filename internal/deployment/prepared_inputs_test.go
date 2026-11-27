// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"testing"

	"github.com/jay94ks/seafield/internal/secrets"
)

// These are product-core counterexamples, authored for the final E7 batch.
func TestPreparedInputsUsesSameMergeFilesAndBudgetWithoutTaskBinding(t *testing.T) {
	f := makeFixture(t)
	b, err := Compile(smallCompose(t), f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	requester := public(private(30))
	n, err := b.inputMetadata("web", requester)
	if err != nil || n.Consumer != "" || n.Generation != 0 {
		t.Fatal("invented consumer", err)
	}
	plans := map[string]secrets.UsePlan{}
	for realm, use := range realmUses(n) {
		batch, err := f.trees[realm].Plan(f.c, []secrets.Use{use})
		if err != nil {
			t.Fatal(err)
		}
		plans[realm] = batch.Uses[0]
	}
	values := f.values(n)
	defer func() {
		for _, v := range values {
			for _, data := range v.Value.Values {
				clear(data)
			}
		}
	}()
	if err = b.CheckPreparedInputs("web", requester, plans, values, 4096); err != nil {
		t.Fatal(err)
	}
	if len(f.bindings.Live()) != 0 {
		t.Fatal("preflight reserved a binding")
	}
	if err = b.CheckPreparedInputs("web", requester, plans, values, 1); err == nil {
		t.Fatal("preflight exceeded actual material budget")
	}
	bad := append([]Fetched(nil), values...)
	bad[0].Value.Reference.Revision++
	if err = b.CheckPreparedInputs("web", requester, plans, bad, 4096); err == nil {
		t.Fatal("wrong fixed revision accepted")
	}
	if err = b.CheckPreparedInputs("web", public(private(31)), plans, values, 4096); err == nil {
		t.Fatal("foreign requester accepted")
	}
	if err = b.CheckPreparedInputs("web", requester, map[string]secrets.UsePlan{}, values, 4096); err == nil {
		t.Fatal("missing plans accepted")
	}
	n.Consumer, n.Generation = "prepared-web", 4
	f.approveAll(n)
	r := f.reserve(n)
	stage, err := r.Bindings[0].Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, values, 4096)
	if err != nil {
		t.Fatal("actual bound materialization differs", err)
	}
	defer stage.Destroy()
	preview, err := materializeInputs(n, plans, values, 4096, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	defer preview.Destroy()
	if len(preview.files) != len(stage.files) {
		t.Fatal("different file set")
	}
	for i, file := range preview.files {
		if file.Projection != stage.files[i].Projection || !bytes.Equal(file.Data, stage.files[i].Data) {
			t.Fatal("different private file")
		}
	}
}
