// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cliprofile"
)

var (
	ErrLoginRequired = errors.New("no saved login for the selected account; use mydc login")
	ErrUserRequired  = errors.New("multiple saved accounts; select one with --user USER")
)

// Account is selection metadata obtained from an authenticated wallet record.
// Expiry/current remote authority is checked AFTER selection and never used to
// silently remove other accounts from an otherwise ambiguous candidate set.
type Account struct {
	Cluster, Profile [32]byte
	Username         string
}

func SelectAccount(accounts []Account, cluster, profile [32]byte, username string) (Account, error) {
	if cluster == [32]byte{} || profile == [32]byte{} || username != "" && !cliprofile.ValidUsername(username) {
		return Account{}, ErrPrivateState
	}
	var candidates []Account
	seen := map[string]bool{}
	for _, account := range accounts {
		if account.Cluster != cluster || account.Profile != profile {
			continue
		}
		if !cliprofile.ValidUsername(account.Username) || seen[account.Username] {
			return Account{}, ErrPrivateState
		}
		seen[account.Username] = true
		candidates = append(candidates, account)
	}
	if username != "" {
		for _, account := range candidates {
			if account.Username == username {
				return account, nil
			}
		}
		return Account{}, ErrLoginRequired
	}
	switch len(candidates) {
	case 0:
		return Account{}, ErrLoginRequired
	case 1:
		return candidates[0], nil
	default:
		names := make([]string, len(candidates))
		for i, account := range candidates {
			names[i] = fmt.Sprintf("%q", account.Username)
		}
		slices.Sort(names)
		return Account{}, fmt.Errorf("%w (available: %s)", ErrUserRequired, strings.Join(names, ", "))
	}
}
