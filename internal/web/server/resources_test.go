// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func bobLogin(t *testing.T, f *fixture) {
	t.Helper()
	if code, out := keyLogin(f, "bob", mydc.FixtureKey("bob")); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
}

// keyLogin runs the browser's key login: challenge, sign the proof, login,
// sign the session approval, approve (R02).
func keyLogin(f *fixture, username string, priv ed25519.PrivateKey) (int, map[string]any) {
	pub := priv.Public().(ed25519.PublicKey)
	code, out := f.do("POST", "/api/v1/auth/key/challenge", map[string]any{"username": username, "publicKey": hex.EncodeToString(pub)})
	if code != 200 {
		return code, out
	}
	proof, _ := base64.StdEncoding.DecodeString(out["proof"].(string))
	code, out = f.do("POST", "/api/v1/auth/key/login", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(priv, proof))})
	if code != 200 || out["approve"] != true {
		return code, out
	}
	approval, _ := base64.StdEncoding.DecodeString(out["approval"].(string))
	return f.do("POST", "/api/v1/auth/key/approve", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(priv, approval))})
}

const (
	opNet1 = "a1b2c3d4-0000-4000-8000-000000000001"
	opNet2 = "a1b2c3d4-0000-4000-8000-000000000002"
	opVol1 = "a1b2c3d4-0000-4000-8000-000000000003"
	opVol2 = "a1b2c3d4-0000-4000-8000-000000000004"
	opVau1 = "a1b2c3d4-0000-4000-8000-000000000005"
	opVau2 = "a1b2c3d4-0000-4000-8000-000000000006"
	opBad  = "a1b2c3d4-0000-4000-8000-000000000007"
)

func opState(t *testing.T, code int, out map[string]any) string {
	t.Helper()
	op, ok := out["op"].(map[string]any)
	if !ok {
		t.Fatalf("no op: %d %v", code, out)
	}
	return op["state"].(string)
}

func hasItem(out map[string]any, field, want string) bool {
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		if inner, ok := m["network"].(map[string]any); ok && field == "network" {
			if inner["name"] == want {
				return true
			}
			continue
		}
		if m[field] == want {
			return true
		}
	}
	return false
}

func networkRow(t *testing.T, f *fixture, name string) map[string]any {
	t.Helper()
	_, list := f.do("GET", "/api/v1/t/shop/networks", nil)
	for _, it := range list["items"].([]any) {
		if n, _ := it.(map[string]any)["network"].(map[string]any); n != nil && n["name"] == name {
			return n
		}
	}
	t.Fatalf("network %s not listed: %v", name, list)
	return nil
}

// signedPayload is the payload of alice's stored signed original.
func signedPayload(t *testing.T, f *fixture, opID string) []byte {
	t.Helper()
	o, err := f.store.GetOp("u-alice", opID)
	if err != nil {
		t.Fatal(err)
	}
	op, err := mydc.DecodeOperation(o.Signed)
	if err != nil {
		t.Fatal(err)
	}
	return op.Change.Payload
}
