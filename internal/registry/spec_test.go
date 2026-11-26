// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestRegistrySpecificationSeparatesListenAuthorityCertificateAndVolumeOwner(t *testing.T) {
	cluster := [32]byte{1}
	s := Specification{Schema: 1, Tenant: "tenant", ID: "private", Node: "node-a", Address: "0.0.0.0:5443", Authority: "registry.example.test:5443", Volume: volumes.Scope{Cluster: cluster, Tenant: "tenant", Registry: "private", ID: "data", Generation: 1}, Enabled: true, Metadata: MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}, Blobs: BlobLimits{BlobBytes: 1 << 20, TotalBytes: 8 << 20, Records: 64}, Budget: workload.Resources{CPU: 1, Memory: 16 << 20}, MaxRequests: 4, MaxHeaderBytes: 8192, RequestTimeoutMS: 30000, TokenSeconds: 60}
	if err := s.Validate(cluster); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Specification){
		"foreign-volume":          func(s *Specification) { s.Volume.Tenant = "other" },
		"fake-app":                func(s *Specification) { s.Volume.App = "pretend" },
		"foreign-registry":        func(s *Specification) { s.Volume.Registry = "other" },
		"credential-in-authority": func(s *Specification) { s.Authority = "user@registry.example.test:5443" },
		"wrong-port":              func(s *Specification) { s.Authority = "registry.example.test:5444" },
		"authority-path":          func(s *Specification) { s.Authority = "registry.example.test:5443/tenant" },
		"schema":                  func(s *Specification) { s.Schema = 2 },
		"unbounded-requests":      func(s *Specification) { s.MaxRequests = 0 },
		"long-token":              func(s *Specification) { s.TokenSeconds = 301 },
	} {
		t.Run(name, func(t *testing.T) {
			next := s
			mutate(&next)
			if next.Validate(cluster) == nil {
				t.Fatal("invalid management scope accepted")
			}
		})
	}
	fixed := s
	fixed.Volume.Registry = ""
	if err := fixed.Validate(cluster); err != nil {
		t.Fatal("pre-registered fixed reference shape", err)
	}
	changed := s
	changed.Authority = "other.example.test:5443"
	if changed.Digest() == s.Digest() {
		t.Fatal("authority not bound to spec")
	}
}
