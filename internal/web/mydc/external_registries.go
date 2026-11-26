// SPDX-License-Identifier: Apache-2.0

package mydc

import "github.com/jay94ks/mydcd/internal/cluster/control"

// REQ-17 private external image registry logins per tenant, in mydcd's
// real shape (docs/reference/external-registries.md). The managed state
// holds only vault references: no credential value appears in a row, a
// payload, a result or a log.

const (
	// put {Spec imagesource.Source}, delete/unbind {Tenant, ID}
	// (control.RegistrySelection), Expected = the record Revision; bind's
	// payload is the plan's Selection (control.ExternalRegistryBind),
	// Expected the plan's Expected.
	ActionPutExternalRegistry    = "put-external-registry"
	ActionDeleteExternalRegistry = "delete-external-registry"
	ActionBindExternalRegistry   = "bind-external-registry"
	ActionUnbindExternalRegistry = "unbind-external-registry"
)

// ExternalRegistryPage: `external-registries` in mydcd's real shape (Reply
// ExternalRegistriesRootRevision / ExternalRegistries / ExternalRegistriesNext),
// 8 a page. Merge pages only while RootRevision stays the same.
type ExternalRegistryPage struct {
	RootRevision uint64
	Items        []control.ExternalRegistryView
	Next         string
}
