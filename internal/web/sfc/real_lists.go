// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/userauth"
)

// realPageSize is the page size of lists the real adapter joins and
// regroups itself (vault): the screen form of a page differs from the sfcd
// rows, so the cursor is the screen key.
const realPageSize = 50

// Tenant lists whose web type is a screen form of the sfcd rows (W1.2
// step 2c).

func (c *realConn) Registries(ctx context.Context, tenant, after string) (Page[RegistryView], error) {
	reply, err := realCall(ctx, c, "registries", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.RegistryPage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return Page[RegistryView]{}, err
	}
	items := make([]RegistryView, 0, len(reply.Registries))
	for _, r := range reply.Registries {
		items = append(items, registryView(r))
	}
	return Page[RegistryView]{Items: items, Next: reply.RegistriesNext, Revision: reply.RegistriesRootRevision}, nil
}

func registryView(r control.RegistryView) RegistryView {
	s := r.Spec
	v := RegistryView{Tenant: s.Tenant, ID: s.ID, Name: s.ID, Endpoint: s.Authority, Revision: r.Revision, Generation: r.Generation,
		Active: r.Active, Node: s.Node, Address: s.Address, Volume: s.Volume.ID, Enabled: s.Enabled,
		Deleted: r.Deleted, Draining: r.Draining, Maintenance: r.Maintenance, Spec: s}
	if r.Observation != nil {
		v.ObservedAt = r.Observation.At
		v.CertificateID = hex.EncodeToString(r.Observation.Certificate[:])
	}
	return v
}

func (c *realConn) ExternalRegistryPage(ctx context.Context, tenant, after string) (ExternalRegistryPage, error) {
	reply, err := realCall(ctx, c, "external-registries", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.ExternalRegistryPage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return ExternalRegistryPage{}, err
	}
	return ExternalRegistryPage{RootRevision: reply.ExternalRegistriesRootRevision, Items: reply.ExternalRegistries, Next: reply.ExternalRegistriesNext}, nil
}

func (c *realConn) VolumeBackups(ctx context.Context, tenant, after string) (Page[VolumeBackupView], error) {
	reply, err := realCall(ctx, c, "volume-backups", func(u userauth.Client, s access.Session) (userauth.VolumeBackupsPage, error) {
		return u.VolumeBackupPage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return Page[VolumeBackupView]{}, err
	}
	items := make([]VolumeBackupView, 0, len(reply.Items))
	for _, b := range reply.Items {
		v := VolumeBackupView{Key: b.Key, Tenant: b.Scope.Tenant, Volume: b.Scope.ID, ID: b.ID, Node: b.Node, Phase: b.Phase,
			Revision: b.Revision, Failure: b.Failure, Source: b}
		if b.Receipt != nil {
			v.Bytes = b.Receipt.Bytes
		}
		items = append(items, v)
	}
	return Page[VolumeBackupView]{Items: items, Next: reply.Next, Revision: reply.RootRevision}, nil
}

func (c *realConn) VolumeRestores(ctx context.Context, tenant, after string) (Page[VolumeRestoreView], error) {
	reply, err := realCall(ctx, c, "volume-restores", func(u userauth.Client, s access.Session) (userauth.VolumeRestoresPage, error) {
		return u.VolumeRestorePage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return Page[VolumeRestoreView]{}, err
	}
	items := make([]VolumeRestoreView, 0, len(reply.Items))
	for _, r := range reply.Items {
		items = append(items, VolumeRestoreView{Key: r.Key, Tenant: r.Target.Tenant, Volume: r.Backup.Scope.ID, Backup: r.Backup.ID, ID: r.ID,
			Node: r.Node, Phase: r.Phase, Target: r.Target.ID, Revision: r.Revision, MaxBytes: r.MaxBytes, CapacityBytes: r.CapacityBytes, Source: r})
	}
	return Page[VolumeRestoreView]{Items: items, Next: reply.Next, Revision: reply.RootRevision}, nil
}

// Vault joins the realm's pages under one root revision: an object's
// display path is the chain of its parent groups, which can sit on other
// pages. Pending write rows are left out (the object's PendingWrite shows
// them).
func (c *realConn) Vault(ctx context.Context, realm, after string) (Page[VaultView], error) {
	const m = "vault"
	var objects []secrets.Object
	var root, tree, approvals uint64
	for next, first := "", true; first || next != ""; first = false {
		reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
			return u.QueryVault(ctx, c.peer, s, realm, next)
		})
		if err != nil {
			return Page[VaultView]{}, err
		}
		if first {
			root, tree, approvals = reply.VaultRootRevision, reply.VaultTreeRevision, reply.VaultApprovalRevision
		} else if reply.VaultRootRevision != root || reply.VaultTreeRevision != tree {
			return Page[VaultView]{}, fail(m, CodeConflict, "vault changed while reading it")
		}
		for _, v := range reply.Vault {
			if v.Object != nil {
				objects = append(objects, *v.Object)
			}
		}
		next = reply.VaultNext
	}
	p := paginate(vaultViews(realm, objects), func(v VaultView) string { return v.Path }, after, realPageSize, root)
	p.Collection, p.ApprovalRevision = tree, approvals
	return p, nil
}

// vaultViews is the screen form of a realm's objects. The root group's
// path is its ID; below it a path is the IDs from the root's child down.
func vaultViews(realm string, objects []secrets.Object) []VaultView {
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
	out := make([]VaultView, 0, len(objects))
	for _, o := range objects {
		v := VaultView{Realm: realm, Path: pathOf(o), Kind: "group", Revision: o.Revision, Protected: o.Protected, ID: o.ID, Parent: o.Parent,
			Status: string(o.Status), PendingWrite: o.PendingWrite, MaxApprovalAge: o.MaxApprovalAge, Keys: []string{},
			ACL: VaultACL{Users: names(o.ACL.Users), Services: names(o.ACL.Services), DenyUsers: names(o.ACL.DenyUsers),
				DenyServices: names(o.ACL.DenyServices), TenantGrants: slices.Clone(o.ACL.TenantGrants)}}
		if v.Parent == "" {
			v.Parent = realm
		}
		if o.Kind == secrets.Secret {
			v.Kind, v.Profile, v.Keys = "object", o.Reference.Profile, names(o.Reference.Keys)
		}
		out = append(out, v)
	}
	return out
}

func names(s []string) []string {
	out := slices.Clone(s)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return out
}

func (c *realConn) VolumeBackupSource(ctx context.Context, tenant string, q control.VolumeSelector) (VolumeSource, error) {
	reply, err := realCall(ctx, c, "volume-backup-source", func(u userauth.Client, s access.Session) (userauth.VolumeBackupSourceReply, error) {
		return u.VolumeBackupSource(ctx, c.peer, s, tenant, q)
	})
	if err != nil {
		return VolumeSource{}, err
	}
	return VolumeSource{Source: reply.Source, VolumeRevision: reply.VolumeRevision}, nil
}

// RegistryCredential: the token is secret and goes straight to the caller.
func (c *realConn) RegistryCredential(ctx context.Context, tenant string, q RegistryCredentialRequest) (RegistryCredential, error) {
	const m = "registry-credential"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.RegistryCredential(ctx, c.peer, s, tenant, userauth.RegistryCredentialRequest{ID: q.ID, Repository: q.Repository, Actions: q.Actions})
	})
	if err != nil {
		return RegistryCredential{}, err
	}
	if len(reply.RegistryCredential) == 0 {
		return RegistryCredential{}, missingReply(m)
	}
	return RegistryCredential{Token: reply.RegistryCredential, Authority: reply.RegistryAuthority, ExpiresAt: reply.RegistryCredentialExpires}, nil
}
