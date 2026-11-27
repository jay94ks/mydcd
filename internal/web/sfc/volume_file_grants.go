// SPDX-License-Identifier: Apache-2.0

package sfc

// REQ-49 (mock): `volume-file-grants`, the REQ-28 folder grants of a
// tenant (volume "" = all). Tenant managers see every row; a granted user
// sees only their own rows. A grant goes away with its volume
// (delete-volume / unregister-fixed); a turned-off user keeps the row with
// Active false (the grant has no effect until the user is on again).

type VolumeFileGrantRow struct {
	Tenant, App, Volume, Prefix string // App "" = tenant-registered volume
	User                        string // user ID
	Username                    string
	Revision                    uint64 // the grant's commit
	GrantedBy                   string // username
	GrantedAt                   int64
	Active                      bool // user enabled
}
