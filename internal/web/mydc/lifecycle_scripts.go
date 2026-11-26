// SPDX-License-Identifier: Apache-2.0

package mydc

// Lifecycle (state check) script REQ mocks. Names follow REQUEST.md
// REQ-39..41 and may change when mydcd publishes them.

// LifecycleUses: REQ-41 (mock) `lifecycle-uses` (ManageServices): the
// accepted app bindings and build jobs that pin a script's versions.
type LifecycleUses struct {
	Tenant, Name string
	Items        []LifecycleUse
}

type LifecycleUse struct {
	Revision           uint64
	Kind               string // app-binding / build-job
	App, Service, Node string `json:",omitempty"`
}
