// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/secrets"
)

// A builtin leaf is served by the builtin profile, which names no key; an
// installed profile must name its owner.
func TestLeafProviderAcceptsBuiltin(t *testing.T) {
	builtin := secrets.BuiltinWriteProfile()
	installed := secrets.WriteProfile{ID: "vault", Key: [32]byte{1}, Enabled: true, Values: true}
	profiles := []secrets.WriteProfile{installed, builtin}
	leaf := func(profile string) secrets.Leaf {
		return secrets.Leaf{Secret: "s", Reference: secrets.Reference{Profile: profile}}
	}
	if p, ok := leafProvider(profiles, leaf(secrets.BuiltinProfile)); !ok || !p.Builtin() {
		t.Fatal("builtin leaf refused")
	}
	if p, ok := leafProvider(profiles, leaf("vault")); !ok || p.Key != installed.Key {
		t.Fatal("installed leaf")
	}
	if _, ok := leafProvider(profiles, leaf("missing")); ok {
		t.Fatal("unknown profile")
	}
	if _, ok := leafProvider([]secrets.WriteProfile{{ID: "vault"}}, leaf("vault")); ok {
		t.Fatal("installed profile without a key")
	}
}
