// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

type accountOptions struct {
	OperationReason *control.OperationReason
	User            string
	Password        walletFD
	NoInput         bool
	Target          cliprofile.Selection
	TenantName      string // explicit --tenant
}
