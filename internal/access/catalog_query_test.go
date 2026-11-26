// SPDX-License-Identifier: Apache-2.0

package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestPublicCatalogPagesBoundScopeRevisionAndSecrets(t *testing.T) {
	c := enrolled(t)
	for i := range 70 {
		u := user(fmt.Sprintf("user-%03d", i), false)
		u.Credentials = append(u.Credentials, Credential{ID: "password", Method: Password, Enabled: true, VerifierRef: "protected-reference-must-not-escape"})
		c = put(t, c, "admin", u)
	}
	var cursor string
	var ids []string
	for {
		rows, next, err := c.UsersPage("admin", cursor)
		if err != nil || len(rows) > catalogPageSize {
			t.Fatal("public page", err)
		}
		raw, _ := json.Marshal(rows)
		if len(raw) > catalogPageBytes+catalogPageSize*2 || strings.Contains(string(raw), "VerifierRef") || strings.Contains(string(raw), "protected-reference") {
			t.Fatal("unbounded page or verifier reference escaped")
		}
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		if next == "" {
			break
		}
		if cursor == "" {
			// A different immutable revision cannot append to this page.
			updated := put(t, c, "admin", user("new", false))
			if _, _, err = updated.UsersPage("admin", next); !errors.Is(err, ErrConflict) {
				t.Fatal("mixed catalog revisions", err)
			}
		}
		cursor = next
	}
	if len(ids) != 71 || ids[0] != "admin" || ids[70] != "user-069" {
		t.Fatal("lost or repeated users", ids)
	}
	rows, _, _ := c.UsersPage("admin", "")
	rows[0].Credentials[0].Enabled = false
	live, _ := c.User("admin")
	if !live.Credentials[0].Enabled {
		t.Fatal("reply aliases catalog")
	}
	if _, _, err := c.UsersPage("user-000", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("non administrator listed accounts", err)
	}
	if _, _, err := c.UsersPage("admin", "invalid-cursor"); !errors.Is(err, ErrInvalid) {
		t.Fatal("malformed cursor", err)
	}
	// Largest legal credential set still fits a single bounded page.
	u := user("large", false)
	u.Credentials = nil
	for i := range 64 {
		k := [32]byte{}
		for j := range k {
			k[j] = 255
		}
		k[0] = byte(i)
		u.Credentials = append(u.Credentials, Credential{Label: strings.Repeat("<", 128), ID: "credential-" + strings.Repeat("a", 45) + fmt.Sprintf("%03d", i), Method: PrivateKey, PublicKey: k, Enabled: true})
	}
	c = put(t, enrolled(t), "admin", u)
	rows, _, err := c.UsersPage("admin", "")
	if err != nil || len(rows) != 2 || len(rows[1].Credentials) != 64 {
		t.Fatal("largest account does not fit", err)
	}
}

func TestTenantMembersPagesKeepNodesMembershipAndEffectiveRolesTogether(t *testing.T) {
	c := enrolled(t)
	c = tenant(t, tenant(t, c, "first"), "second")
	for i := range 70 {
		id := fmt.Sprintf("member-%03d", i)
		c = put(t, c, "admin", user(id, false))
		c = member(t, c, "first", id, Viewer, i != 2)
	}
	c = member(t, c, "first", "member-000", Manager, true)
	c = put(t, c, "admin", user("foreign", false))
	c = member(t, c, "second", "foreign", Manager, true)
	nodes := []string{}
	for i := range 85 {
		nodes = append(nodes, fmt.Sprintf("node-%03d", i))
	}
	first, _ := c.Tenant("first")
	var err error
	c, err = c.SetNodes("admin", "first", first.Revision, nodes)
	if err != nil {
		t.Fatal(err)
	}
	var cursor string
	var seenUsers, seenNodes []string
	for {
		rows, allowed, next, err := c.TenantMembersPage("member-000", "first", cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.User == "foreign" {
				t.Fatal("foreign member leaked")
			}
			if row.User == "member-002" && (row.Enabled || len(row.Actions) != 0) {
				t.Fatal("disabled membership has actions")
			}
			if row.User == "member-001" && !reflect.DeepEqual(row.Actions, []Action{Read}) {
				t.Fatal("viewer actions", row.Actions)
			}
			if row.User == "member-000" && (!slices.Contains(row.Actions, CallService) || c.Authorize(row.User, "first", CallService, "") != nil) {
				t.Fatal("manager service-call action missing", row.Actions)
			}
			if row.User == "admin" && (!row.Implicit || row.Role != Manager || len(row.Actions) != len(tenantMemberActions)) {
				t.Fatal("implicit admin", row)
			}
			if row.User == "admin" && !slices.Contains(row.Actions, CallService) {
				t.Fatal("implicit admin service-call action missing", row.Actions)
			}
			seenUsers = append(seenUsers, row.User)
		}
		seenNodes = append(seenNodes, allowed...)
		if next == "" {
			break
		}
		if _, _, _, err := c.TenantMembersPage("admin", "second", next); !errors.Is(err, ErrInvalid) {
			t.Fatal("cursor crossed tenants", err)
		}
		updated := member(t, c, "first", "member-001", Manager, true)
		if _, _, _, err := updated.TenantMembersPage("admin", "first", next); !errors.Is(err, ErrConflict) {
			t.Fatal("membership revision not bound", err)
		}
		cursor = next
	}
	if len(seenUsers) != 71 || !reflect.DeepEqual(seenNodes, nodes) {
		t.Fatal("paging lost members or allowed nodes", len(seenUsers), len(seenNodes))
	}
	for _, actor := range []string{"foreign", "member-001", "member-002", "missing"} {
		if _, _, _, err := c.TenantMembersPage(actor, "first", ""); !errors.Is(err, ErrDenied) {
			t.Fatal("unauthorized membership query", actor, err)
		}
	}
	for _, enabled := range []bool{true, false} {
		changed := member(t, c, "first", "member-000", Viewer, enabled)
		rows, _, _, err := changed.TenantMembersPage("admin", "first", "")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range rows {
			if row.User != "member-000" {
				continue
			}
			found = true
			if slices.Contains(row.Actions, CallService) || changed.Authorize(row.User, "first", CallService, "") == nil || enabled && !reflect.DeepEqual(row.Actions, []Action{Read}) || !enabled && len(row.Actions) != 0 {
				t.Fatal("revoked manager still exposes service-call authority", row)
			}
		}
		if !found {
			t.Fatal("revoked manager missing from public membership page")
		}
	}
}
