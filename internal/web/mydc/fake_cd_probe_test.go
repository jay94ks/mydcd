// SPDX-License-Identifier: Apache-2.0

package mydc

import "testing"

// cd-probe reads a Git source once and changes nothing.
func TestCDProbe(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	q := cdProbeRequest{Tenant: "shop", App: "php-shop", Repository: "https://git.example.com/shop/app.git", Branch: "main", Path: "app.yaml"}
	before, _ := alice.AppRevisions(ctx, "shop", "php-shop", "")
	journal := len(f.Journal())

	r, err := alice.(*fakeConn).probeCD(ctx, q)
	if err != nil || r.Code != "" || r.Commit == "" || r.Size == 0 || r.Node != "node-a" {
		t.Fatalf("public %+v %v", r, err)
	}
	for _, c := range []struct {
		mod  func(*cdProbeRequest)
		code string
	}{
		{func(x *cdProbeRequest) { x.Repository = "https://git.example.com/shop/private.git" }, CDProbeAuthFailed},
		{func(x *cdProbeRequest) {
			x.Repository, x.Credential = "https://git.example.com/shop/private.git", "nope"
		}, CDProbeNoCredential},
		{func(x *cdProbeRequest) { x.Path = "deploy/app.yaml" }, CDProbeNoFile},
		{func(x *cdProbeRequest) { x.Branch = "release" }, CDProbeNoBranch},
		{func(x *cdProbeRequest) { x.Repository = "https://git.example.com/missing.git" }, CDProbeNoRepository},
		{func(x *cdProbeRequest) { x.Repository = "https://unreachable.example.com/a.git" }, CDProbeTimeout},
	} {
		x := q
		c.mod(&x)
		if r, err := alice.(*fakeConn).probeCD(ctx, x); err != nil || r.Code != c.code {
			t.Fatalf("%+v → %+v %v, want %s", x, r, err, c.code)
		}
	}
	x := q
	x.Repository, x.Credential = "https://git.example.com/shop/private.git", "git-deploy"
	if r, _ := alice.(*fakeConn).probeCD(ctx, x); r.Code != "" || r.Size == 0 {
		t.Fatalf("private with credential %+v", r)
	}
	f.SetGitSource("https://git.example.com/shop/app.git", "abc123", map[string]string{"deploy/app.yaml": "name: x\n"})
	f.SetGitBranches("https://git.example.com/shop/app.git", "main", "release")
	x = q
	x.Branch, x.Path = "release", "deploy/app.yaml"
	if r, _ := alice.(*fakeConn).probeCD(ctx, x); r.Code != "" || r.Size != 8 || r.Commit == "" {
		t.Fatalf("set source %+v", r)
	}

	// Input, permission, app.
	for _, bad := range []func(*cdProbeRequest){
		func(x *cdProbeRequest) { x.Repository = "http://git.example.com/a.git" },
		func(x *cdProbeRequest) { x.Repository = "https://user:pw@git.example.com/a.git" },
		func(x *cdProbeRequest) { x.Path = "../app.yaml" },
		func(x *cdProbeRequest) { x.Branch = "" },
		func(x *cdProbeRequest) { x.Credential = "Bad Name" },
	} {
		x := q
		bad(&x)
		_, err := alice.(*fakeConn).probeCD(ctx, x)
		wantCode(t, err, CodeInvalid)
	}
	_, err = bob.(*fakeConn).probeCD(ctx, q)
	wantCode(t, err, CodeDenied)
	x = q
	x.App = "nope"
	_, err = alice.(*fakeConn).probeCD(ctx, x)
	wantCode(t, err, CodeMissing)

	// Rate limit: 10 a minute per user (9 used above).
	x = q
	x.Repository = "https://git.example.com/shop/other.git"
	if r, _ := alice.(*fakeConn).probeCD(ctx, x); r.Code != "" {
		t.Fatalf("10th %+v", r)
	}
	if r, _ := alice.(*fakeConn).probeCD(ctx, q); r.Code != CDProbeRateLimited {
		t.Fatalf("11th %+v", r)
	}

	// Nothing changed.
	after, _ := alice.AppRevisions(ctx, "shop", "php-shop", "")
	if len(after.Items) != len(before.Items) || len(f.Journal()) != journal {
		t.Fatalf("probe changed state")
	}
}
