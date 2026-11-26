// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func TestCheckerBuildMemberReportCannotCreateOrphanJob(t *testing.T) {
	f := newCheckerFixture(t)
	f.apply("manager", "set-lifecycle-policy", 0, checkerPolicy(), state.Applied)
	id := sha256.Sum256([]byte("original-job"))
	fact := checkerFact(f, f.node, "package checker\n")
	b := checker.BuildIntent{Schema: 1, Cluster: f.p.Cluster, Tenant: "tenant", ID: hex.EncodeToString(id[:]), AppUseID: "missing-parent", AppUse: [32]byte{1}, Node: "node-a", Owner: fact.Owner, Selection: checker.Selection{PolicyRevision: 1, Sources: []checker.SourceFact{fact}}, Inputs: []checker.BuildInput{{Content: fact.ContentDigest(), Recipe: [32]byte{2}}}, Manifest: [32]byte{3}, Target: "linux/amd64", DeadlineUnixMilli: 10000}
	r := CheckerBuildReport{Schema: 1, Cluster: f.p.Cluster, Reporter: fact.Owner, Tenant: b.Tenant, ID: b.ID, Action: "reserve", Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(LifecycleKey).Revision, Index: f.s.Index(), At: 2, Intent: &b}
	r.Signature = ed25519.Sign(f.node, CheckerBuildReportBytes(r))
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveCheckerBuildReport(f.s, fact.Owner, raw)
	if err != nil || !f.p.AdmitModule(f.s, cmd) {
		t.Fatal("member report envelope", err)
	}
	before, _ := f.p.Lifecycles(f.s)
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Forbidden {
		t.Fatal("orphan build admitted", result, err)
	}
	after, err := f.p.Lifecycles(n)
	if err != nil || after.Revision() != before.Revision() || len(after.BuildJobs()) != 0 {
		t.Fatal("denial changed metadata", err)
	}
	r.Intent = nil // retain original signature: action/payload cannot be changed
	raw, _ = json.Marshal(r)
	if _, err := f.p.ResolveCheckerBuildReport(f.s, fact.Owner, raw); err == nil {
		t.Fatal("changed signed report")
	}
}

func TestCheckerBuildTaskProjectionRejectsInterpretedAndUnrelatedAlias(t *testing.T) {
	f := newCheckerFixture(t)
	fact := checkerFact(f, f.node, "package checker\n")
	ref := checker.NamedReference{Name: "ready", Revision: 1}
	b := checker.BuildIntent{Selection: checker.Selection{Scripts: []checker.NamedReference{ref}}, Inputs: []checker.BuildInput{{Content: fact.ContentDigest()}}}
	p := checker.TaskProgram{Scripts: map[string]checker.ScriptSelection{"alias": {Ref: &ref, Compile: true}}, Sources: map[string]checker.SourceFact{"alias": fact}}
	if checkerBuildProgramAllowed(b, p) != nil {
		t.Fatal("exact compiled source")
	}
	s := p.Scripts["alias"]
	s.Compile = false
	p.Scripts["alias"] = s
	if checkerBuildProgramAllowed(b, p) == nil {
		t.Fatal("interpreted source compiled")
	}
	s.Compile = true
	other := checker.NamedReference{Name: "foreign", Revision: 1}
	s.Ref = &other
	p.Scripts["alias"] = s
	if checkerBuildProgramAllowed(b, p) == nil {
		t.Fatal("same bytes widened original named alias")
	}
}
