// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"
	"testing"
)

func TestU0AccountSelectionNeverChoosesAmongMultipleUsers(t *testing.T) {
	cluster, profile := [32]byte{1}, [32]byte{2}
	alice := Account{Cluster: cluster, Profile: profile, Username: "alice"}
	bob := Account{Cluster: cluster, Profile: profile, Username: "bob"}
	otherCluster := Account{Cluster: [32]byte{3}, Profile: profile, Username: "other"}
	otherProfile := Account{Cluster: cluster, Profile: [32]byte{4}, Username: "other"}
	for _, test := range []struct {
		name, user string
		accounts   []Account
		want       Account
		failure    error
	}{
		{"none", "", nil, Account{}, ErrLoginRequired},
		{"one", "", []Account{alice}, alice, nil},
		{"two", "", []Account{alice, bob}, Account{}, ErrUserRequired},
		{"reversed", "", []Account{bob, alice}, Account{}, ErrUserRequired},
		{"explicit", "bob", []Account{alice, bob}, bob, nil},
		{"missing-explicit", "nobody", []Account{alice}, Account{}, ErrLoginRequired},
		{"scope", "", []Account{otherCluster, otherProfile, alice}, alice, nil},
		{"duplicate", "alice", []Account{alice, alice}, Account{}, ErrPrivateState},
		{"invalid", "alice\n", []Account{alice}, Account{}, ErrPrivateState},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := SelectAccount(test.accounts, cluster, profile, test.user)
			if got != test.want || !errors.Is(err, test.failure) {
				t.Fatal(got, err)
			}
		})
	}
}
