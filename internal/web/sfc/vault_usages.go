// SPDX-License-Identifier: Apache-2.0

package sfc

// VaultUsage: REQ-44 (mock) `vault-usages` row, one app service that takes
// secrets from the queried object (a group: itself or anything under it; a
// secret: itself or a group above it). Name follows REQUEST.md REQ-44 and
// may change when sfcd publishes it.
type VaultUsage struct {
	App, Deployment, Service string
	Standalone               string `json:",omitempty"` // not modeled by the fake yet
	Node                     string
	Selector                 string   // the secrets_from entry: secret ID or group ID
	Secrets                  []string // secret object IDs it receives that the query covers
	// Live: the usage still holds (the app is deployed); vault-retire is
	// refused while one is live.
	Live bool
}
