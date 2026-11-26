// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/registry"
)

// RegistryCredential in the fake: tenant managers only (the fixture has no
// deploy-only role); the registry must be enabled and active. The token is
// random; nothing is kept.
func (c *fakeConn) RegistryCredential(ctx context.Context, tenant string, q RegistryCredentialRequest) (RegistryCredential, error) {
	const m = "registry-credential"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return RegistryCredential{}, err
	}
	defer c.unlock()
	w := c.f.w
	repo, actions, err := registry.RequestedScope("repository:" + q.Repository + ":" + joinActions(q.Actions))
	if err != nil || repo != q.Repository || !slices.Equal(actions, q.Actions) || !w.canManage(user, tenant) {
		return RegistryCredential{}, fail(m, CodeDenied, "")
	}
	i := slices.IndexFunc(w.registries, func(r RegistryView) bool { return r.Tenant == tenant && r.ID == q.ID })
	if i < 0 || w.registries[i].Deleted || !w.registries[i].Enabled || !w.registries[i].Active {
		return RegistryCredential{}, fail(m, CodeDenied, "")
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	r := w.registries[i]
	return RegistryCredential{Token: []byte("mydc-fake-registry-login." + hex.EncodeToString(b)), Authority: r.Spec.Authority,
		ExpiresAt: c.f.now().Unix() + int64(r.Spec.TokenSeconds)}, nil
}

func joinActions(a []string) string { return strings.Join(a, ",") }
