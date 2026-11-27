// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func TestAppSourcePlanBindsExactDocumentScopeAndDeclaredLocks(t *testing.T) {
	raw := []byte("name: demo\nx-sfc:\n  lifecycle:\n    scripts:\n      inline: {source: 'package checker'}\nservices:\n  web:\n    image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n    x-sfc:\n      lifecycle:\n        checks: [{id: ready, phase: readiness, script: inline}]\n")
	doc, err := deployment.ParseApp(raw)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := doc.Sfc.Lifecycle.Scripts["inline"].Descriptor("tenant")
	if err != nil {
		t.Fatal(err)
	}
	p := AppSourcePlan{Schema: 1, Cluster: [32]byte{1}, User: "alice", Tenant: "tenant", Document: sha256.Sum256(raw), Sources: map[string]checker.SourceDescriptor{"inline": descriptor}}
	if err := p.Check(raw, p.Cluster, p.User, p.Tenant); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(p)
	decoded, err := DecodeAppSourcePlan(encoded)
	if err != nil || decoded.Check(raw, p.Cluster, p.User, p.Tenant) != nil {
		t.Fatal("read-only metadata roundtrip", err)
	}
	if p.Check(append(append([]byte(nil), raw...), '\n'), p.Cluster, p.User, p.Tenant) == nil || p.Check(raw, p.Cluster, "other", p.Tenant) == nil || p.Check(raw, [32]byte{2}, p.User, p.Tenant) == nil || p.Check(raw, p.Cluster, p.User, "other") == nil {
		t.Fatal("preparation changed scope/document")
	}
	for _, change := range []func(*AppSourcePlan){
		func(p *AppSourcePlan) { delete(p.Sources, "inline") },
		func(p *AppSourcePlan) { p.Sources["extra"] = descriptor },
		func(p *AppSourcePlan) { d := descriptor.Clone(); d.Digest[0]++; p.Sources["inline"] = d },
		func(p *AppSourcePlan) {
			d := descriptor.Clone()
			d.Modules = []checker.ModulePin{{Path: "example.invalid/checker", Version: "v1.0.0", Digest: [32]byte{2}, Length: 1024}}
			p.Sources["inline"] = d
		},
	} {
		copy, err := DecodeAppSourcePlan(encoded)
		if err != nil {
			t.Fatal(err)
		}
		change(&copy)
		if copy.Check(raw, p.Cluster, p.User, p.Tenant) == nil {
			t.Fatal("metadata changed exact source declaration")
		}
	}
}
