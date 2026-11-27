// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Query assembly runs only after the handler's admission and user authorization.
// Each helper receives the original committed view and preserves that view for
// both root revisions and page contents. No helper refreshes state or authority.

func (s Service) registryQueryReply(view cluster.View, session access.Session, request Request, reply Reply) Reply {
	reply.ExternalRegistriesRootRevision = view.State.Object(control.ExternalRegistriesKey).Revision
	if request.Method == "external-registries" {
		var err error
		reply.ExternalRegistries, reply.ExternalRegistriesNext, err = s.Policy.ExternalRegistryPage(view.State, session, time.Now().Unix(), request.Tenant, request.After)
		if err != nil {
			return Reply{Schema: 1, Code: "denied"}
		}
		return reply
	}
	reply.RegistriesRootRevision = view.State.Object(control.RegistriesKey).Revision
	reply.RegistryMaintenanceRootRevision = view.State.Object(control.RegistryMaintenanceKey).Revision
	reply.ImageBuildRootRevision = view.State.Object(control.ImageBuildKey).Revision
	if request.Method == "registries" {
		book, err := s.Policy.Registries(view.State)
		if err != nil {
			reply = Reply{Schema: 1, Code: "unavailable"}
		} else {
			reply.RegistriesRevision = book.Revision
			reply.Registries, reply.RegistriesNext, err = s.Policy.RegistryPage(view.State, session, time.Now().Unix(), request.Tenant, request.After)
			if err != nil {
				reply = Reply{Schema: 1, Code: "denied"}
			}
		}
	}

	return reply
}

func (s Service) storageQueryReply(view cluster.View, catalog access.Catalog, session access.Session, request Request, reply Reply) Reply {
	reply.NodeStorageRootRevision = view.State.Object(control.NodeStorageKey).Revision
	if request.Method == "tenant-storage" {
		page, err := s.Policy.TenantStoragePage(view.State, session, time.Now().Unix(), request.Tenant, request.Node, request.After)
		if err != nil {
			if err == access.ErrConflict {
				return Reply{Schema: 1, Code: "conflict"}
			}
			return Reply{Schema: 1, Code: "denied"}
		}
		reply.TenantStorage, reply.TenantStorageNext, reply.TenantStorageViewIndex = page.Items, page.Next, page.Index
		reply.NodeStorageRevision = page.Revision
		return reply
	}
	if request.Method == "node-storage" {
		roots, err := s.Policy.NodeStorage(view.State)
		if err != nil {
			reply = Reply{Schema: 1, Code: "unavailable"}
		} else {
			reply.NodeStorageRevision = roots.Revision()
			reply.NodeStorage, reply.NodeStorageNext, err = s.Policy.NodeStoragePage(view.State, catalog, session.User, request.Node, request.After)
			if err != nil {
				reply = Reply{Schema: 1, Code: "denied"}
			}
		}
	}

	return reply
}

func (s Service) vaultQueryReply(view cluster.View, catalog access.Catalog, session access.Session, request Request, reply Reply) Reply {
	reply.VaultRootRevision = view.State.Object(control.VaultKey).Revision
	if request.Method == "vault" {
		v, err := s.Policy.Vault(view.State)
		if err != nil {
			reply = Reply{Schema: 1, Code: "unavailable"}
		} else {
			reply.VaultRevision, reply.VaultApprovalRevision = v.Revision, v.Approvals.Revision()
			if tree, ok := v.Trees[request.Tenant]; ok {
				reply.VaultTreeRevision, reply.VaultWriteEpoch = tree.Revision(), tree.WriteEpoch()
			}
			reply.Vault, reply.VaultNext, err = v.Page(catalog, session.User, request.Tenant, request.After)
			if err != nil {
				reply = Reply{Schema: 1, Code: "denied"}
			}
		}
	}

	return reply
}

func (s Service) appsQueryReply(view cluster.View, catalog access.Catalog, session access.Session, request Request, reply Reply) Reply {
	reply.AppsRootRevision = view.State.Object(control.AppsKey).Revision
	if apps, err := s.Policy.Apps(view.State); err == nil {
		reply.AppRevision = apps.Revision
		if request.Method == "apps" {
			reply.Apps, reply.AppsNext, err = apps.ObservedPage(catalog, session.User, request.Tenant, request.After, uint64(time.Now().Unix()))
			if err == nil {
				for i := range reply.Apps {
					if err = s.Policy.ObserveAppReplicaHealth(view.State, apps, &reply.Apps[i], uint64(time.Now().Unix())); err != nil {
						break
					}
					s.Policy.ObserveAppCD(view.State, apps, catalog, &reply.Apps[i], uint64(time.Now().Unix()))
				}
			}
		} else if request.Method == "app-operation" {
			var operation control.AppOperationView
			operation, err = apps.Operation(catalog, session.User, request.Tenant, *request.AppOperation)
			if err == nil {
				reply.AppOperation = &operation
			}
		} else {
			reply.Uploads, reply.UploadsNext, err = apps.Uploads(catalog, session.User, request.Tenant, request.After)
		}
		if err != nil {
			reply = Reply{Schema: 1, Code: "denied"}
		}
	} else {
		reply = Reply{Schema: 1, Code: "unavailable"}
	}

	return reply
}
