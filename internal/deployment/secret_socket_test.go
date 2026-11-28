// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/secrets"
)

func socketCompose(t *testing.T, edit func(string) string) (Compose, error) {
	t.Helper()
	doc := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	doc = strings.Replace(doc, "secrets: {from: [defaults, group/common, overrides]}", "secrets: {from: [defaults, group/common, overrides], socket: [group/common, overrides]}", 1)
	if edit != nil {
		doc = edit(doc)
	}
	return ParseCompose([]byte(doc))
}

func TestSecretSocketKeyIsAccepted(t *testing.T) {
	c, err := socketCompose(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := c.Services["web"].Sfc.Socket
	if len(got) != 2 || got[0].Group != "common" || got[1].Secret != "overrides" || got[0].Scope != "tenant" {
		t.Fatalf("socket = %+v", got)
	}
}

func TestSecretSocketRefusals(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"mount over /run/sfc": func(s string) string {
			return strings.Replace(s, "    secrets: [db-password]\n    depends_on", "    secrets: [db-password]\n    tmpfs: [/run/sfc]\n    depends_on", 1)
		},
		"mount under /run/sfc": func(s string) string {
			return strings.Replace(s, "    secrets: [db-password]\n    depends_on", "    secrets: [db-password]\n    tmpfs: [/run/sfc/x]\n    depends_on", 1)
		},
		"env name taken": func(s string) string {
			return strings.Replace(s, "environment: {DB_HOST: db,", "environment: {SFC_SECRET_SOCKET: /x, DB_HOST: db,", 1)
		},
		"duplicate source": func(s string) string {
			return strings.Replace(s, "socket: [group/common, overrides]", "socket: [overrides, overrides]", 1)
		},
	} {
		if _, err := socketCompose(t, edit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Without a socket the same names are the user's own.
	doc := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	doc = strings.Replace(doc, "environment: {DB_HOST: db,", "environment: {SFC_SECRET_SOCKET: /x, DB_HOST: db,", 1)
	if _, err := ParseCompose([]byte(doc)); err != nil {
		t.Fatalf("no socket, own env name refused: %v", err)
	}
}

// A socket service asks for its own sfev approval, separate from the file
// approval of the same groups, and only for the socket's sources.
func TestSecretSocketApprovalIsItsOwnPurpose(t *testing.T) {
	f := makeFixture(t)
	c, err := socketCompose(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := contextFor(t, f)
	if _, err := Compile(c, f.c, ctx); err == nil || !strings.Contains(err.Error(), "secret-socket") {
		t.Fatalf("socket planned before sfcd serves it: %v", err)
	}
	ctx.Features["secret-socket"] = true
	b, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, ok, err := b.SocketMetadata("web", [32]byte{9})
	if err != nil || !ok {
		t.Fatalf("socket metadata = %v %v", ok, err)
	}
	if n.Use.Purpose != secrets.PurposeSecretSocket || len(n.Files) != 0 || len(n.Sources) != 2 || n.Sources[0].Object != "common" || n.Sources[1].Object != "overrides" {
		t.Fatalf("socket needs = %+v", n)
	}
	in, err := b.Inputs("web", "web-task", 3, [32]byte{9})
	if err != nil || in.Socket == nil || in.Socket.Generation != 1 || len(in.Socket.Sources) != 2 || !useEqual(socketInputNeeds(in).Use, n.Use) {
		t.Fatalf("task inputs socket = %+v %v", in.Socket, err)
	}
	if _, ok, err := b.SocketMetadata("db", [32]byte{9}); ok || err != nil {
		t.Fatalf("db has no socket: %v %v", ok, err)
	}
	uses, err := b.ApprovalUses([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	var file, socket []string
	for _, u := range uses["tenant"] {
		if u.Service != "web" {
			continue
		}
		switch u.Purpose {
		case "":
			file = u.Sources
		case secrets.PurposeSecretSocket:
			socket = u.Sources
		default:
			t.Fatalf("purpose %q", u.Purpose)
		}
	}
	if len(file) != 3 || strings.Join(socket, ",") != "common,overrides" {
		t.Fatalf("file %v socket %v", file, socket)
	}
	if SocketConsumer("app-x") == SocketConsumer("app-y") || !identifier(SocketConsumer("app-x")) {
		t.Fatal("socket consumer")
	}
}

func TestTaskSecretSocketRuntimeUpdateAcceptsOnlyRevisionChanges(t *testing.T) {
	base := ComposeService{Image: "img@sha256:" + strings.Repeat("a", 64), SocketRevisions: "r1"}
	base.Sfc.Socket = SecretSources{{Secret: "api", Scope: "tenant"}}
	claim, step := aliasClaim(t, base)
	if TaskSecretSocketRuntimeUpdate(claim, step) {
		t.Fatal("unchanged Task reported as an update instead of Keep")
	}
	next := base
	next.SocketRevisions = "r2"
	target := step
	target.Goal = goal(next)
	if !TaskSecretSocketRuntimeUpdate(claim, target) {
		t.Fatal("revision-only change requires replacement")
	}
	for name, mutate := range map[string]func(*ComposeService){
		"sources": func(s *ComposeService) { s.Sfc.Socket = SecretSources{{Secret: "other", Scope: "tenant"}} },
		"removed": func(s *ComposeService) { s.Sfc.Socket = nil },
		"image":   func(s *ComposeService) { s.Image = "img@sha256:" + strings.Repeat("b", 64) },
	} {
		n := next
		mutate(&n)
		target := step
		target.Goal = goal(n)
		if TaskSecretSocketRuntimeUpdate(claim, target) {
			t.Fatal("other change treated as a socket renewal", name)
		}
	}
	for name, change := range map[string]func(*Claim, *Step){
		"removed":   func(c *Claim, _ *Step) { c.Removed = true },
		"unapplied": func(c *Claim, _ *Step) { c.Result.Code = state.Forbidden },
		"owner":     func(_ *Claim, s *Step) { s.Owner = [32]byte{2} },
		"command":   func(c *Claim, _ *Step) { c.Command.Value = "{" },
	} {
		c, s := claim, target
		change(&c, &s)
		if TaskSecretSocketRuntimeUpdate(c, s) {
			t.Fatal("renewal accepted without the exact original Task", name)
		}
	}
}

// The same app.yaml after a socket secret changed differs only in that
// Task's socket revision, which TaskSecretSocketRuntimeUpdate recognizes;
// the file inputs stay pinned to their own sources.
func TestSocketRevisionLandsInTheTaskGoal(t *testing.T) {
	f := makeFixture(t)
	c, err := socketCompose(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	rev := map[string]int{}
	ctx := contextFor(t, f)
	ctx.Features["secret-socket"] = true
	ctx.SecretRevisions = func(sources []Source) string {
		out := ""
		for _, s := range sources {
			out += s.Object + "=" + string(rune('0'+rev[s.Object])) + ";"
		}
		return out
	}
	plan := func() map[string]Step {
		b, err := Compile(c, f.c, ctx)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(b.d)
		if _, err := DecodeBlueprint(raw); err != nil {
			t.Fatal("decode:", err)
		}
		out := map[string]Step{}
		for _, s := range b.Steps() {
			out[s.Key] = s
		}
		return out
	}
	before := plan()
	task := ResourceKey("task", "tenant", "php-mysql", "web")
	var s ComposeService
	if json.Unmarshal(before[task].Goal, &s) != nil || s.SocketRevisions != "common=0;overrides=0;" {
		t.Fatalf("socket revision = %q", s.SocketRevisions)
	}
	rev["common"]++
	after := plan()
	claim, _ := aliasClaim(t, ComposeService{})
	claim.Step = before[task]
	original := GoalCommand{Schema: 1, Kind: "task", Tenant: "tenant", App: "php-mysql", Node: claim.Step.Node, Owner: claim.Step.Owner, Config: before[task].Goal}
	claim.Command.Key, claim.Command.Value = task, string(goal(original))
	if !TaskSecretSocketRuntimeUpdate(claim, after[task]) {
		t.Fatal("socket secret change is not a renewal")
	}
	db := ResourceKey("task", "tenant", "php-mysql", "db")
	if string(before[db].Goal) != string(after[db].Goal) {
		t.Fatal("db has no socket but its goal changed")
	}
}

// A Binding with a socket holds a separate sfev grant (own consumer per task
// generation, own generation) next to its file grants, survives its codec,
// and its closure releases both.
func TestBindingReservesAndReleasesSocketGrants(t *testing.T) {
	f := makeFixture(t)
	n := f.web()
	n.Socket = &SocketNeeds{Sources: []Source{{Realm: "tenant", Object: "common"}, {Realm: "", Object: "overrides"}}, Generation: 1}
	targets := f.approveAll(n)
	var socket int
	for _, target := range targets {
		if target.Purpose == secrets.PurposeSecretSocket {
			socket++
		}
	}
	if socket == 0 {
		t.Fatal("no sfev approval asked")
	}
	r := f.reserve(n)
	b := r.Bindings[0]
	grants := b.SocketGrants()
	if len(grants) != 2 || len(b.ProjectionGrants()) == 0 || len(b.Grants()) != len(b.ProjectionGrants())+2 {
		t.Fatalf("grants: projection %d socket %d", len(b.ProjectionGrants()), len(grants))
	}
	for _, g := range grants {
		if g.Use.Purpose != secrets.PurposeSecretSocket || g.Consumer == n.Consumer || g.Generation != 1 || len(g.Use.Sources) != 1 {
			t.Fatalf("socket grant = %+v", g)
		}
	}
	raw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := DecodeBinding(raw); err != nil || back.Digest() != b.Digest() {
		t.Fatalf("codec: %v", err)
	}
	// The next task generation has another socket consumer.
	next := n
	next.Generation++
	if socketInputNeeds(next).Consumer == socketInputNeeds(n).Consumer {
		t.Fatal("socket consumer shared across task generations")
	}
	out, err := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, f.closure(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range b.Grants() {
		if _, ok := out.Approvals.Usage(g); ok {
			t.Fatalf("grant %s kept after closure", g.Consumer)
		}
	}
	// Without a socket nothing changes in the binding's shape.
	plain := f.web()
	if len(realms(socketInputNeeds(plain))) != 0 {
		t.Fatal("socket grant without a socket")
	}
}

// A socket service's native recipe asks for the socket directory, and its
// resolved process names the socket; neither is the user's to set.
func TestTaskRecipeAsksForTheSecretSocket(t *testing.T) {
	_, b, material := taskMaterialFixtureIn(t, makeFixture(t), func(c *Compose) {
		db := c.Services["db"]
		db.Sfc.Socket = slices.Clone(c.Services["web"].Sfc.Sources[1:])
		c.Services["db"] = db
	}, func(ctx *PlanningContext) { ctx.Features["secret-socket"] = true })
	if material.Binding.Needs().Socket == nil {
		t.Fatal("binding has no socket needs")
	}
	_, spec, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil || !spec.SecretSocket {
		t.Fatalf("recipe: socket=%t err=%v", spec.SecretSocket, err)
	}
	_, plain, material := taskMaterialFixtureWith(t, nil)
	if _, spec, err = plain.taskRecipe("db", material, material.Bridge.Owner); err != nil || spec.SecretSocket {
		t.Fatalf("plain recipe: socket=%t err=%v", spec.SecretSocket, err)
	}
}
