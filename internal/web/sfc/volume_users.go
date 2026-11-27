// SPDX-License-Identifier: Apache-2.0

package sfc

// VolumeUsers: REQ-37 (mock) `volume-users` (tenant Read) for a volume name,
// optionally one app. Name follows REQUEST.md REQ-37 and may change when
// sfcd publishes it.
type VolumeUsers struct {
	Tenant, Volume string
	Users          []VolumeUser
	ObservedAt     int64
}

// VolumeUser is one app service or standalone container that mounts the
// volume. Kind: NetworkUserService / NetworkUserStandalone. Attached: a
// container of it is running with the mount now (else only the definition
// asks for it); the attached count matches VolumeView.Consumers.
type VolumeUser struct {
	Kind                     string
	App, Service, Standalone string `json:",omitempty"`
	Node                     string `json:",omitempty"`
	ReadOnly                 bool
	Attached                 bool
	Selection                []ContainerSelection `json:",omitempty"`
}
