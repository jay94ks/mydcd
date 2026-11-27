// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A cluster registry login stays in sfcd: it is never printed or serialized,
// and a malformed one is refused before a client is made.
func TestRegistryAuthIsRedactedAndScoped(t *testing.T) {
	const authority = "registry.example.test:5443"
	const secret = "short-task-login-secret"
	auth, err := NewRegistryAuth(authority, "sfc-task", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	defer auth.source.Close()
	if strings.Contains(fmt.Sprint(auth), secret) || strings.Contains(fmt.Sprintf("%+v", auth), secret) {
		t.Fatal("auth formatter leaked")
	}
	if _, err = json.Marshal(auth); err == nil {
		t.Fatal("request credential serialized to general JSON")
	}
	for _, bad := range []struct{ authority, user, password string }{{"", "u", "p"}, {"a/b", "u", "p"}, {authority, "", "p"}, {authority, "u", ""}} {
		if _, err := NewRegistryAuth(bad.authority, bad.user, []byte(bad.password)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
