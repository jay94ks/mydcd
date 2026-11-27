// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"

	"github.com/jay94ks/seafield/internal/deployment"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// AppSourcePlan is read-only preparation metadata. It attests no cache bytes,
// source permission receipt, app reservation, compiler start or native health.
type AppSourcePlan struct {
	Schema       uint8
	Cluster      [32]byte
	User, Tenant string
	Document     [32]byte
	Sources      map[string]checker.SourceDescriptor
}

func (p AppSourcePlan) Check(document []byte, cluster [32]byte, user, tenant string) error {
	if p.Schema != 1 || cluster == ([32]byte{}) || user == "" || tenant == "" || p.Cluster != cluster || p.User != user || p.Tenant != tenant || p.Document != sha256.Sum256(document) {
		return ErrCatalog
	}
	c, err := deployment.ParseApp(document)
	if err != nil || c.Sfc.Tenant != "" && c.Sfc.Tenant != tenant {
		return ErrCatalog
	}
	program, _, err := c.LifecycleProgram()
	if err != nil {
		return err
	}
	count := 0
	for alias, script := range program.Scripts {
		if script.Ref != nil {
			continue
		}
		count++
		d, err := script.Descriptor(tenant)
		got, ok := p.Sources[alias]
		if err != nil || !ok || got.Validate() != nil || got.ContentDigest() != d.ContentDigest() || got.Tenant != tenant {
			return ErrCatalog
		}
	}
	if count != len(p.Sources) {
		return ErrCatalog
	}
	return nil
}

func DecodeAppSourcePlan(raw []byte) (AppSourcePlan, error) {
	var p AppSourcePlan
	if len(raw) > deployment.ArtifactMaxBytes || canonical(raw, &p) != nil || p.Schema != 1 {
		return AppSourcePlan{}, ErrCatalog
	}
	return p, nil
}
