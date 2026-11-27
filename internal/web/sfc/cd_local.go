// SPDX-License-Identifier: Apache-2.0

package sfc

import "github.com/jay94ks/seafield/internal/cluster/control"

// Services the web adds to a CD app, kept apart from Git (sfcd's local
// services). put-app-local-services names an app upload holding an
// app.yaml-style document with only those services; it becomes part of the
// next candidate, and a sync or approval runs it. clear-app-local-services
// drops them at the next sync. A Git service with the same name blocks
// sync (the row's Blocked "name-conflict").

const (
	ActionPutAppLocalServices   = "put-app-local-services"
	ActionClearAppLocalServices = "clear-app-local-services"
)

// AppLocalChange: put-app-local-services / clear-app-local-services.
// Expected = the CD revision; Revision = AppCDLocal.LocalRevision exactly;
// Registration and Target from AppCDLocal (Target pins the execution the
// change was made against).
type AppLocalChange = control.AppLocalChange

// AppCDLocal: the CD row's local services and the pending document
// (`app-source` section pending-local; tenant Read).
type AppCDLocal struct {
	Tenant, App string
	// Revision: the CD revision (the changes' Expected); LocalRevision the
	// local part's revision (AppLocalChange.Revision; 0 = never set).
	Revision, LocalRevision uint64
	Actor                   string `json:",omitempty"` // who set it last
	// Document: the pending local part, an app.yaml fragment with only
	// `services:` ("" = none).
	Document    string
	Services    []string // local
	GitServices []string // the running Git document's; locked in the web
	// Conflicts: local names the running Git document also has.
	Conflicts    []string `json:",omitempty"`
	Registration [32]byte `json:"-"`
	Target       [32]byte `json:"-"` // AppCDView.LocalTarget
}
