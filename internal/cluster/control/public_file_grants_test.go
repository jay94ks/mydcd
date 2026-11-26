// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"slices"
	"testing"
)

// The fixture consumes the RQ9 grant/revoke reducer and Catalog projection.
// It adds no read-side delegation registry or native file-transfer claims.
func addPublicFileGrantUser(t *testing.T, f *backupCoreFixture, id string) access.Session {
	t.Helper()
	if !slices.Contains(f.session.Scopes[0].Actions, access.ManageMembers) {
		f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
		f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	}
	user := access.User{ID: id, Username: id, Enabled: true, AutomationOnly: true, Credentials: []access.Credential{{ID: "file", Method: access.PrivateKey, PublicKey: [32]byte(f.admin.Public().(ed25519.PublicKey)), Enabled: true, Operations: []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}}}}
	f.apply("file-user-"+id, "put-user", 0, user, state.Applied)
	f.apply("file-member-"+id, "set-membership", 0, access.Membership{Tenant: "tenant", User: id, Enabled: true, Role: access.Viewer}, state.Applied)
	c, _ := f.p.Catalog(f.s)
	user, _ = c.User(id)
	session := f.session
	session.User = id
	session.Credential = "file"
	session.AccountRevision = user.Revision
	session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	return session
}
func setPublicFileGrant(t *testing.T, f *backupCoreFixture, id string, g access.VolumeFileFolderGrant, revoke bool) {
	t.Helper()
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	action := "volume-file-grant"
	if revoke {
		action = "volume-file-revoke"
	}
	f.apply(id, action, c.Revision(), g, state.Applied)
}
func readPublicFileGrants(t *testing.T, f *backupCoreFixture, session access.Session, q PublicReadQuery, after string) PublicReadPage {
	t.Helper()
	page, err := f.p.PublicRead(f.s, session, 10, "volume-file-grants", "tenant", q, after)
	if err != nil {
		t.Fatal(err)
	}
	return page
}
func TestFileGrantListUsesOriginalFolderGrantReducerAndCurrentAccount(t *testing.T) {
	f := newBackupCore(t)
	own := addPublicFileGrantUser(t, f, "delegate")
	other := addPublicFileGrantUser(t, f, "other")
	g := access.VolumeFileFolderGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: "mydc-web-backups/", User: own.User}
	setPublicFileGrant(t, f, "grant-folder", g, false)
	c, _ := f.p.Catalog(f.s)
	stored := c.VolumeFileGrants("tenant", own.User, "app", "data")
	if len(stored) != 1 {
		t.Fatal("fixture did not use original grant reducer")
	}
	before, _ := state.Encode(f.s)
	q := PublicReadQuery{Name: "data", App: "app"}
	page := readPublicFileGrants(t, f, f.session, q, "")
	if len(page.Rows) != 1 || page.Total != 1 || page.Rows[0].FileGrant == nil {
		t.Fatal("manager did not see original delegation", page)
	}
	row := page.Rows[0].FileGrant
	if row.Prefix != g.Prefix || row.User != own.User || row.Revision != stored[0].Revision || !row.VolumePresent || !row.AccountEnabled || page.RootRevision != f.s.Object(CatalogKey).Revision {
		t.Fatal("folder grant source/revision mismatch", row)
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("grant read changed authoritative state")
	}
	if page := readPublicFileGrants(t, f, own, q, ""); len(page.Rows) != 1 || page.Rows[0].FileGrant.User != own.User {
		t.Fatal("delegate cannot see own original folder grant", page)
	}
	if page := readPublicFileGrants(t, f, other, q, ""); len(page.Rows) != 0 || page.Total != 0 || page.Next != "" {
		t.Fatal("other reader learned hidden delegation counts", page)
	}
	c, _ = f.p.Catalog(f.s)
	user, _ := c.User(own.User)
	user.Enabled = false
	expected := user.Revision
	user.Revision = 0
	f.apply("disable-delegate", "put-user", expected, user, state.Applied)
	page = readPublicFileGrants(t, f, f.session, q, "")
	if len(page.Rows) != 1 || page.Rows[0].FileGrant.AccountEnabled || page.Rows[0].FileGrant.Revision != stored[0].Revision {
		t.Fatal("account mutation replaced or hid folder grant", page)
	}
	if _, err := f.p.PublicRead(f.s, own, 10, "volume-file-grants", "tenant", q, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("disabled account retained metadata authority", err)
	}
	setPublicFileGrant(t, f, "revoke-folder", g, true)
	page = readPublicFileGrants(t, f, f.session, q, "")
	if len(page.Rows) != 0 || page.Total != 0 {
		t.Fatal("revoke retained a read-side shadow grant", page)
	}
}
func TestFileGrantReadSelectorsPaginationAndTenantBoundary(t *testing.T) {
	f := newBackupCore(t)
	own := addPublicFileGrantUser(t, f, "delegate")
	other := addPublicFileGrantUser(t, f, "other")
	for i := 0; i < 10; i++ {
		setPublicFileGrant(t, f, fmt.Sprintf("grant-page-%02d", i), access.VolumeFileFolderGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: fmt.Sprintf("backups/%02d/", i), User: own.User}, false)
	}
	setPublicFileGrant(t, f, "grant-other-reader", access.VolumeFileFolderGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: "other-private/", User: other.User}, false)
	// An empty app/name selector enumerates the chosen tenant, never grant scope.
	page := readPublicFileGrants(t, f, own, PublicReadQuery{}, "")
	if len(page.Rows) != 8 || page.Total != 10 || page.Next == "" {
		t.Fatal("original grants did not use shared pagination", page)
	}
	next := readPublicFileGrants(t, f, own, PublicReadQuery{}, page.Next)
	if len(next.Rows) != 2 || next.Total != 10 || next.Next != "" {
		t.Fatal("grant continuation lost original visible rows", next)
	}
	if page := readPublicFileGrants(t, f, own, PublicReadQuery{App: "other-app"}, ""); page.Total != 0 {
		t.Fatal("app selector ignored", page)
	}
	if page := readPublicFileGrants(t, f, own, PublicReadQuery{Name: "another"}, ""); page.Total != 0 {
		t.Fatal("Volume selector ignored", page)
	}
	if _, err := f.p.PublicRead(f.s, own, 10, "volume-file-grants", "foreign", PublicReadQuery{}, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("other tenant existence exposed", err)
	}
	g := access.VolumeFileFolderGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: "backups/00/", User: own.User}
	setPublicFileGrant(t, f, "revoke-page", g, true)
	if _, err := f.p.PublicRead(f.s, own, 10, "volume-file-grants", "tenant", PublicReadQuery{}, page.Next); !errors.Is(err, access.ErrConflict) {
		t.Fatal("revocation reused a stale grant page", err)
	}
	fresh := readPublicFileGrants(t, f, own, PublicReadQuery{}, "")
	if fresh.Total != 9 {
		t.Fatal("revoke not reflected by original state", fresh)
	}
	raw, _ := json.Marshal(fresh)
	for _, private := range []string{"other-private/", "Credential", "VerifierRef", "Signature", "Session"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("public folder-grant page leaked unrelated/private metadata", private)
		}
	}
}
func TestCredentialFileCeilingIsNotListedAsAnIssuedFolderGrant(t *testing.T) {
	f := newBackupCore(t)
	own := addPublicFileGrantUser(t, f, "delegate")
	c, _ := f.p.Catalog(f.s)
	user, _ := c.User(own.User)
	user.Credentials[0].VolumeFiles = []access.VolumeFileGrant{{Tenant: "tenant", App: "app", Volume: "data", Prefix: "credential-only/", Operations: []string{"volume-file-get"}}}
	expected := user.Revision
	user.Revision = 0
	f.apply("credential-ceiling", "put-user", expected, user, state.Applied)
	page := readPublicFileGrants(t, f, f.session, PublicReadQuery{}, "")
	if len(page.Rows) != 0 || page.Total != 0 {
		t.Fatal("credential ceiling masqueraded as grant/revoke state", page)
	}
	g := access.VolumeFileFolderGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: "issued/", User: own.User}
	setPublicFileGrant(t, f, "grant-with-ceiling", g, false)
	page = readPublicFileGrants(t, f, f.session, PublicReadQuery{}, "")
	if len(page.Rows) != 1 || page.Rows[0].FileGrant.Prefix != "issued/" {
		t.Fatal("read projected credential rather than issued folder grant", page)
	}
}

func TestFileGrantMissingVolumeIsVisibleAsMetadataOnly(t *testing.T) {
	f := newBackupCore(t)
	own := addPublicFileGrantUser(t, f, "delegate")
	g := access.VolumeFileFolderGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: "backups/", User: own.User}
	setPublicFileGrant(t, f, "grant-before-volume-removal", g, false)
	// Consume the same projection against an empty registry snapshot. This
	// read-only fixture claims no actual deletion, owner Gone or Volume fence.
	c, _ := f.p.Catalog(f.s)
	empty := f.view()
	delete(empty.entries, f.scope.Key())
	writes, code := f.p.volumeCheckpoint(f.s, empty)
	if code != state.Applied {
		t.Fatal(code)
	}
	var err error
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "fixture-missing-volume", Key: VolumesKey, Expected: f.s.Object(VolumesKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := current.publicFileGrants(f.s, c, f.session, 10, "tenant", PublicReadQuery{})
	if err != nil || len(rows) != 1 || rows[0].FileGrant.VolumePresent {
		t.Fatal("missing Volume hid source grant or inferred a live target", rows, err)
	}
}
