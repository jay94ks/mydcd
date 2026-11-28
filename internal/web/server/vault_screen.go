// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// screenVault joins every sfcd vault page of realm under one revision (a
// path needs every ancestor, which may be on another page) and pages the
// screen rows (vaultViews) after the path after. Revision is RootRevision,
// Collection TreeRevision (vault-create Expected), ApprovalRevision the
// Approvals revision.
func screenVault(ctx context.Context, c sfc.Conn, realm, after string) (sfc.Page[sfc.VaultView], error) {
	var objects []secrets.Object
	var first sfc.Page[control.VaultView]
	for next, i := "", 0; i == 0 || next != ""; i++ {
		p, err := c.Vault(ctx, realm, next)
		if err != nil {
			return sfc.Page[sfc.VaultView]{}, err
		}
		if i == 0 {
			first = p
		} else if p.Revision != first.Revision || p.Collection != first.Collection {
			return sfc.Page[sfc.VaultView]{}, &sfc.Error{Method: "vault", Code: sfc.CodeConflict, Detail: "vault changed while reading it"}
		}
		for _, v := range p.Items {
			if v.Object != nil {
				objects = append(objects, *v.Object)
			}
		}
		if p.Next == next {
			break
		}
		next = p.Next
	}
	items := vaultViews(realm, objects)
	slices.SortFunc(items, func(a, b sfc.VaultView) int { return strings.Compare(a.Path, b.Path) })
	out := sfc.Page[sfc.VaultView]{Revision: first.Revision, Collection: first.Collection, ApprovalRevision: first.ApprovalRevision}
	for _, v := range items {
		if v.Path <= after {
			continue
		}
		if len(out.Items) == screenPageSize {
			out.Next = out.Items[len(out.Items)-1].Path
			break
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}

// vaultViews is the screen form of a realm's objects. The root group's
// path is its ID and its parent the realm; below it a path is the IDs from
// the root's child down.
func vaultViews(realm string, objects []secrets.Object) []sfc.VaultView {
	byID := map[string]secrets.Object{}
	for _, o := range objects {
		byID[o.ID] = o
	}
	pathOf := func(o secrets.Object) string {
		if o.Parent == "" {
			return o.ID
		}
		parts := []string{o.ID}
		for p, seen := byID[o.Parent], 0; p.Parent != "" && seen < len(objects); p, seen = byID[p.Parent], seen+1 {
			parts = append(parts, p.ID)
		}
		slices.Reverse(parts)
		return strings.Join(parts, "/")
	}
	out := make([]sfc.VaultView, 0, len(objects))
	for _, o := range objects {
		v := sfc.VaultView{Realm: realm, Path: pathOf(o), Kind: "group", Revision: o.Revision, Protected: o.Protected, ID: o.ID, Parent: o.Parent,
			Status: string(o.Status), PendingWrite: o.PendingWrite, MaxApprovalAge: o.MaxApprovalAge, Keys: []string{},
			ACL: sfc.VaultACL{Users: vaultNames(o.ACL.Users), Services: vaultNames(o.ACL.Services), DenyUsers: vaultNames(o.ACL.DenyUsers),
				DenyServices: vaultNames(o.ACL.DenyServices), TenantGrants: slices.Clone(o.ACL.TenantGrants)}}
		if v.Parent == "" {
			v.Parent = realm
		}
		if o.Kind == secrets.Secret {
			v.Kind, v.Profile, v.Keys = "object", o.Reference.Profile, vaultNames(o.Reference.Keys)
		}
		out = append(out, v)
	}
	return out
}

func vaultNames(s []string) []string {
	out := slices.Clone(s)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return out
}
