// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"

	"gopkg.in/yaml.v3"
)

func TestManagementInputRejectsDHCPServerAndKeepsCIDRIPAMTyped(t *testing.T) {
	for _, action := range []string{"configure-network-dhcp", "approve-dhcp-client"} {
		raw, _ := json.Marshal(ChangeDocument{Schema: 1, Action: action, Payload: json.RawMessage(`{}`)})
		if _, err := InputChange(raw, "current-admin"); err == nil {
			t.Fatal("removed DHCP management action accepted", action)
		}
	}
	base := `{"schema":1,"action":"create-network","payload":{"Tenant":"tenant","ID":"lan","Node":"node-a","Pools":[{"ID":"pool","Prefix":"10.81.0.0/24","Gateway":"10.81.0.1","MTU":1280,"IPAM":{"Dynamic":"10.81.0.0/25"}}]}}`
	change, err := InputChange([]byte(base), "current-admin")
	if err != nil || change.Action != "create-network" || !bytes.Contains(change.Payload, []byte(`"Dynamic":"10.81.0.0/25"`)) {
		t.Fatal("typed CIDR/Docker IPAM metadata lost", err)
	}
	var raw map[string]any
	if err = json.Unmarshal([]byte(base), &raw); err != nil {
		t.Fatal(err)
	}
	payload := raw["payload"].(map[string]any)
	ipam := payload["Pools"].([]any)[0].(map[string]any)["IPAM"].(map[string]any)
	ipam["DHCP"] = map[string]any{"First": "10.81.0.128", "Last": "10.81.0.223"}
	bad, _ := json.Marshal(raw)
	if _, err = InputChange(bad, "current-admin"); err == nil {
		t.Fatal("removed DHCP envelope silently discarded")
	}
}

func TestManagementInputUsesSessionPrincipalAndTypedPublicMetadata(t *testing.T) {
	raw := []byte(` {"schema":1,"action":"create-tenant","payload":{"ID":"alpha"}} `)
	change, err := InputChange(raw, "current-admin")
	if err != nil || change.Principal != "current-admin" || change.Expected != 0 || !bytes.Equal(change.Payload, []byte(`{"ID":"alpha"}`)) {
		t.Fatal("typed change", err)
	}
	user := access.User{ID: "alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "password", Method: access.Password, VerifierRef: "vault/system/system/credentials/alice/password@1", Enabled: true}}}
	payload, _ := json.Marshal(user)
	doc, _ := json.Marshal(ChangeDocument{Schema: 1, Action: "put-user", Expected: 7, Payload: payload})
	change, err = InputChange(doc, "current-admin")
	if err != nil || change.Expected != 7 || !bytes.Equal(change.Payload, payload) {
		t.Fatal("public credential reference or target CAS changed", err)
	}
	bad := []string{
		`{"schema":1,"action":"create-tenant","principal":"other","payload":{"ID":"alpha"}}`,
		`{"schema":1,"action":"create-tenant","payload":{"id":"alpha"}}`,
		`{"schema":1,"action":"create-tenant","payload":{"ID":"alpha","ID":"beta"}}`,
		`{"schema":1,"action":"put-user","payload":{"ID":"alice","Credentials":[{"ID":"pw","Password":"secret"}]}}`,
		`{"schema":1,"action":"put-user","payload":{"ID":"alice","Token":"secret"}}`,
		`{"schema":1,"action":"grant-node-authority","payload":{}}`,
		`{"schema":2,"action":"create-tenant","payload":{"ID":"alpha"}}`,
	}
	for i, raw := range bad {
		if _, err = InputChange([]byte(raw), "current-admin"); err == nil {
			t.Fatalf("unsafe change %d accepted", i)
		}
	}
	if _, err = InputChange(doc, ""); err == nil {
		t.Fatal("missing authenticated principal accepted")
	}
}

// changeInput is the manage apply document of one change. A []byte payload
// is used as is; anything else is marshaled.
func changeInput(action string, expected uint64, payload any) []byte {
	raw, ok := payload.([]byte)
	if !ok {
		raw, _ = json.Marshal(payload)
	}
	doc, _ := json.Marshal(ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: raw})
	return doc
}

// yamlPayload turns a YAML payload into JSON so tests can write payloads
// the way people write them.
func yamlPayload(t *testing.T, s string) []byte {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReplacementActionsRequireEveryReplacedField(t *testing.T) {
	for action, fields := range replacedFields {
		full := map[string]any{}
		for _, key := range fields {
			full[key] = map[string]any{"Enabled": true, "Members": []any{}}
		}
		raw, _ := json.Marshal(full)
		if !explicitFields(action, raw) {
			t.Fatal("named replacement rejected", action)
		}
		for _, key := range fields {
			for _, value := range []any{nil, "omit"} {
				partial := map[string]any{}
				for k, v := range full {
					partial[k] = v
				}
				if value == nil {
					partial[key] = nil
				} else {
					delete(partial, key)
				}
				raw, _ := json.Marshal(partial)
				if explicitFields(action, raw) {
					t.Fatal("omitted or null replacement field became a reset", action, key)
				}
			}
		}
	}
	if !explicitFields("create-network", []byte(`[]`)) {
		t.Fatal("an action without replaced fields was checked")
	}
}
