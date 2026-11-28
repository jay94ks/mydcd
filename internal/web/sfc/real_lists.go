// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
)

// realPageSize is the page size of lists the real adapter joins and
// regroups itself (vault): the screen form of a page differs from the sfcd
// rows, so the cursor is the screen key.
const realPageSize = 50

// Tenant lists whose web type is a screen form of the sfcd rows (W1.2
// step 2c).

func (c *realConn) Registries(ctx context.Context, tenant, after string) (userauth.RegistriesPage, error) {
	return realCall(ctx, c, "registries", func(u userauth.Client, s access.Session) (userauth.RegistriesPage, error) {
		return u.RegistryPage(ctx, c.peer, s, tenant, after)
	})
}

func (c *realConn) ExternalRegistryPage(ctx context.Context, tenant, after string) (userauth.ExternalRegistriesPage, error) {
	return realCall(ctx, c, "external-registries", func(u userauth.Client, s access.Session) (userauth.ExternalRegistriesPage, error) {
		return u.ExternalRegistryPage(ctx, c.peer, s, tenant, after)
	})
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

func (c *realConn) VolumeArchives(ctx context.Context, tenant, after string) (userauth.VolumeArchivesPage, error) {
	return realCall(ctx, c, "volume-archives", func(u userauth.Client, s access.Session) (userauth.VolumeArchivesPage, error) {
		return u.VolumeArchivePage(ctx, c.peer, s, tenant, after)
	})
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
func (c *realConn) Vault(ctx context.Context, realm, after string) (Page[control.VaultView], error) {
	reply, err := realCall(ctx, c, "vault", func(u userauth.Client, s access.Session) (userauth.VaultPage, error) {
		return u.QueryVault(ctx, c.peer, s, realm, after)
	})
	if err != nil {
		return Page[control.VaultView]{}, err
	}
	return Page[control.VaultView]{Items: reply.Items, Next: reply.Next, Revision: reply.RootRevision, Collection: reply.TreeRevision, ApprovalRevision: reply.ApprovalRevision}, nil
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

// RegistryCredential: the credential is secret and goes straight to the
// caller.
func (c *realConn) RegistryCredential(ctx context.Context, tenant string, q RegistryCredentialRequest) (userauth.RegistryCredential, error) {
	return realCall(ctx, c, "registry-credential", func(u userauth.Client, s access.Session) (userauth.RegistryCredential, error) {
		return u.RegistryCredential(ctx, c.peer, s, userauth.RegistryCredentialQuery{Tenant: tenant, ID: q.ID, Repository: q.Repository, Actions: q.Actions})
	})
}
