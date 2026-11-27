// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/servicecall"
)

// REQ-24/55 and REQ-56 in sfcd's real shape.
func TestServiceCallAndProbeReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	q := servicecall.Request{App: "php-shop", Service: "web", Port: 8080, Path: "/decide", Method: "POST",
		Headers: map[string]string{"Content-Type": "application/json", "X-SFC-Event": "cd-approval-required"}, Body: []byte(`{}`)}

	r, err := alice.CallService(ctx, "shop", q)
	if err != nil || !r.Valid() || r.Status != 200 || r.Headers["Content-Type"] != "application/json" || string(r.Body) != `{"ok":true}` || r.Node != "node-a" {
		t.Fatalf("call %+v %v", r, err)
	}
	f.SetServiceResponder("shop", "php-shop", "web", func(ServiceCallRequest) ServiceResponse { return ServiceResponse{Refused: true, ElapsedMS: 5} })
	if r, err := alice.CallService(ctx, "shop", q); err != nil || r.Code != servicecall.Refused || !r.Valid() || r.Node != "" {
		t.Fatalf("refused %+v %v", r, err)
	}
	f.SetServiceResponder("shop", "php-shop", "web", nil)
	https := q
	https.Scheme, https.Port = "https", 8080
	if r, _ := alice.CallService(ctx, "shop", https); r.Code != servicecall.TLS {
		t.Fatalf("https to plain %+v", r)
	}
	for _, bad := range []func(*servicecall.Request){
		func(x *servicecall.Request) { x.Method = "GET" },
		func(x *servicecall.Request) { x.Path = "//evil/x" },
		func(x *servicecall.Request) { x.Headers = map[string]string{"Authorization": "x"} },
		func(x *servicecall.Request) { x.InsecureSkipVerify = true },
	} {
		x := q
		bad(&x)
		if _, err := alice.CallService(ctx, "shop", x); err == nil {
			t.Fatalf("accepted %+v", x)
		}
	}
	big := q
	big.Body = make([]byte, servicecall.MaxBody+1)
	if r, err := alice.CallService(ctx, "shop", big); err != nil || r.Code != servicecall.TooLarge {
		t.Fatalf("big %+v %v", r, err)
	}
	if _, err := bob.CallService(ctx, "shop", q); err == nil {
		t.Fatal("viewer called a service")
	}

	p := deployment.GitProbeRequest{App: "php-shop", Repository: "https://git.example.com/shop/app.git", Branch: "main", Path: "app.yaml"}
	pr, err := alice.ProbeCD(ctx, "shop", p)
	if err != nil || !pr.Valid() || pr.Code != "" || pr.Size == 0 || pr.Node != "node-a" {
		t.Fatalf("probe %+v %v", pr, err)
	}
	rel := p
	rel.Branch = "release"
	f.SetGitBranches(p.Repository, "main", "release")
	if pr, err := alice.ProbeCD(ctx, "shop", rel); err != nil || !pr.Valid() || pr.Code != "" {
		t.Fatalf("branch probe %+v %v", pr, err)
	}
	miss := p
	miss.Path = "deploy/app.yaml"
	if pr, err := alice.ProbeCD(ctx, "shop", miss); err != nil || pr.Code != "no-file" || !pr.Valid() || pr.Commit != "" {
		t.Fatalf("no file %+v %v", pr, err)
	}
	refs := p
	refs.Branch = "refs/heads/main"
	if _, err := alice.ProbeCD(ctx, "shop", refs); err == nil {
		t.Fatal("refs/heads/ branch accepted")
	}
}
