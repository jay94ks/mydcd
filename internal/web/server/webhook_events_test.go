// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func TestWebhookIncidentDecideAndNotify(t *testing.T) {
	f, fake, clock := incidentFixture(t)
	hs := newHookServer(t, f)
	ctx := context.Background()
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "mydc-autofix", "a1b2c3d4-0000-4000-8000-0000000000a1", true, true)
	if code, out := f.do("PUT", "/api/v1/incidents/policy", map[string]any{"revision": 0, "level": "auto-low", "ratePerHour": 5,
		"approvers": map[string]any{"label": "관리자", "deadlineMinutes": 30}, "quiet": []string{}, "newAppDefault": "suggest"}); code != 200 {
		t.Fatalf("policy: %d %v", code, out)
	}
	for _, h := range []map[string]any{
		{"name": "ops", "kind": "external", "url": hs.URL + "/ops", "role": "notify"},
		{"name": "judge", "kind": "external", "url": hs.URL + "/judge", "role": "decide"},
	} {
		if code, out := f.do("POST", "/api/v1/webhooks", h); code != 201 {
			t.Fatalf("webhook: %d %v", code, out)
		}
	}
	_, pol := f.do("GET", "/api/v1/incidents/policy", nil)
	if fmt.Sprint(pol["decide"]) != "[ai rules]" || pol["decideNow"] != "rules" {
		t.Fatalf("decide before link: %v %v %v", pol["decide"], pol["decideNow"], pol["decideSkip"])
	}
	for _, l := range []map[string]any{
		{"point": "incident", "scope": map[string]any{}, "webhook": "ops", "events": []string{"opened", "auto-run"}},
		{"point": "incident", "scope": map[string]any{}, "webhook": "judge"},
	} {
		if code, out := f.do("POST", "/api/v1/webhook-links", l); code != 201 {
			t.Fatalf("link: %d %v", code, out)
		}
	}
	_, pol = f.do("GET", "/api/v1/incidents/policy", nil)
	if fmt.Sprint(pol["decide"]) != "[ai webhook rules]" || pol["decideNow"] != "webhook" || fmt.Sprint(pol["decideSkip"]) != "map[ai:no-key]" {
		t.Fatalf("decide: %v %v %v", pol["decide"], pol["decideNow"], pol["decideSkip"])
	}

	// An answer outside the candidates is dropped; the rules decide.
	hs.mu.Lock()
	hs.answer = `{"action":"scale-app","reason":"더 늘려요"}`
	hs.mu.Unlock()
	fake.AddEvent(mydc.FixtureEvent{Time: clock.Load(), Scope: "cluster", Node: "node-c", Kind: "node-unreachable", Target: "node-c"})
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	row := findIncident(t, f, "node-unreachable")
	_, det := f.do("GET", "/api/v1/incidents/"+row["id"].(string), nil)
	tl := fmt.Sprint(det["timeline"])
	if !strings.Contains(tl, "accepted:false") || !strings.Contains(tl, "scale-app은(는) allowed_actions에 없습니다") || !strings.Contains(tl, "webhook:judge") {
		t.Fatalf("dropped answer: %v", tl)
	}
	var events []string
	hs.mu.Lock()
	for _, r := range hs.got {
		events = append(events, r.URL.Path+":"+r.Header.Get("X-MyDC-Event"))
	}
	hs.mu.Unlock()
	if s := strings.Join(events, ","); !strings.Contains(s, "/judge:incident.decide") || !strings.Contains(s, "/ops:incident.opened") {
		t.Fatalf("sent: %s", s)
	}

	// "none" hands the incident to a person.
	hs.mu.Lock()
	hs.answer = `{"action":"none","reason":"사람이 볼게요"}`
	hs.mu.Unlock()
	fake.AddEvent(mydc.FixtureEvent{Time: clock.Load(), Scope: "node", Node: "node-b", Kind: "node-resource-low", Target: "node-b:/srv/mydc-ssd"})
	clock.Add(1)
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	row = findIncident(t, f, "node-resource-low")
	if row == nil || decisionOf(row) != "none" {
		t.Fatalf("none: %v", row)
	}
	_, ds := f.do("GET", "/api/v1/webhooks/judge/deliveries", nil)
	if d := ds["items"].([]any)[0].(map[string]any); d["decision"] != "none" || d["accepted"] != true {
		t.Fatalf("judge delivery: %v", d)
	}
}

func TestWebhookCDChecks(t *testing.T) {
	f, fake, _ := incidentFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	calls := map[string][]mydc.ServiceCallRequest{}
	answers := map[string]string{"/pre": `{"decision":"pass","reason":"검사 통과"}`, "/post": `{"result":"fail","reason":"오류율 9%"}`, "/chat": `ok`}
	fake.SetServiceResponder("shop", "php-shop", "web", func(q mydc.ServiceCallRequest) mydc.ServiceResponse {
		mu.Lock()
		defer mu.Unlock()
		calls[q.Path] = append(calls[q.Path], q)
		return mydc.ServiceResponse{Status: 200, ContentType: "application/json", Body: []byte(answers[q.Path])}
	})
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "mydc-autofix", "a1b2c3d4-0000-4000-8000-0000000000a2", true, true)
	// Incident response stays off: CD links alone keep the watcher reading.
	fakeLogin(t, f, "alice")
	for _, h := range []map[string]any{
		{"name": "pre", "tenant": "shop", "kind": "internal", "target": map[string]any{"app": "php-shop", "service": "web", "port": 8080, "path": "/pre"}, "role": "decide"},
		{"name": "post", "tenant": "shop", "kind": "internal", "target": map[string]any{"app": "php-shop", "service": "web", "port": 8080, "path": "/post"}, "role": "decide"},
		{"name": "chat", "tenant": "shop", "kind": "internal", "target": map[string]any{"app": "php-shop", "service": "web", "port": 8080, "path": "/chat"}, "role": "notify", "format": "slack"},
	} {
		if code, out := f.do("POST", "/api/v1/webhooks", h); code != 201 {
			t.Fatalf("webhook: %d %v", code, out)
		}
	}
	scope := map[string]any{"tenant": "shop", "app": "php-shop"}
	for _, l := range []map[string]any{
		{"point": "cd", "scope": scope, "webhook": "pre", "kind": "pre-sync"},
		{"point": "cd", "scope": scope, "webhook": "post", "kind": "post-sync", "when": "synced", "onFail": "pause-rollback"},
		{"point": "cd", "scope": scope, "webhook": "chat", "kind": "notify", "events": []string{"approved", "paused"}},
	} {
		if code, out := f.do("POST", "/api/v1/webhook-links", l); code != 201 {
			t.Fatalf("link: %d %v", code, out)
		}
	}
	_, ls := f.do("GET", "/api/v1/webhook-links?point=cd&app=php-shop", nil)
	if !strings.Contains(fmt.Sprint(ls), "account:mydc-autofix scope:ApproveCD shop/php-shop state:ok") {
		t.Fatalf("approver: %v", ls)
	}

	// A new commit waits for approval: the pre-sync webhook passes it.
	fakeLogin(t, f, "admin")
	f.srv.watchOnce(ctx) // start reading
	fakeLogin(t, f, "alice")
	fake.SetCDCandidate("shop", "php-shop", "c0ffee1", strings.Replace(phpShopDoc(t, f), "php-shop:1.4.2", "php-shop:1.5.0", 1))
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	_, cd := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd", nil)
	if w, _ := cd["webhook"].(map[string]any); w == nil || w["state"] != "passed" {
		t.Fatalf("pre-sync: %v", cd)
	}
	approved := false
	for _, e := range fake.Journal() {
		if e.User == "u-mydc-autofix" && e.Action == mydc.ActionApproveAppCD {
			approved = true
		}
	}
	if !approved || !strings.Contains(string(calls["/pre"][0].Body), `"commit":"c0ffee1"`) {
		t.Fatalf("approved as the automation account: %v %v", fake.Journal(), calls["/pre"])
	}

	// The sync succeeded; the post-sync webhook says it failed: CD pauses
	// and an incident proposes the previous version (with approval).
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	f.srv.watchOnce(ctx) // cd-approved / cd-paused notices
	f.srv.hooks.wg.Wait()
	_, cd = f.do("GET", "/api/v1/t/shop/apps/php-shop/cd", nil)
	pc, _ := cd["webhook"].(map[string]any)
	if pc == nil || pc["kind"] != "post-sync" || pc["state"] != "failed" || pc["reason"] != "오류율 9%" ||
		!strings.Contains(fmt.Sprint(pc["actions"]), "kind:pause state:done") || !strings.Contains(fmt.Sprint(pc["actions"]), "incident:inc-") {
		t.Fatalf("post-sync: %v", cd)
	}
	paused := false
	for _, e := range fake.Journal() {
		if e.User == "u-mydc-autofix" && e.Action == mydc.ActionPauseAppCD {
			paused = true
		}
	}
	if !paused {
		t.Fatalf("not paused: %v", fake.Journal())
	}
	fakeLogin(t, f, "admin")
	if row := findIncident(t, f, "cd-post-check-failed"); row == nil || row["decision"].(map[string]any)["kind"] == "auto" {
		t.Fatalf("incident: %v", row)
	}
	// The history row of that candidate carries both checks.
	_, hist := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/history", nil)
	var row map[string]any
	for _, x := range hist["items"].([]any) {
		if m := x.(map[string]any); m["commit"] == "c0ffee1" {
			row = m
		}
	}
	if cs, _ := row["checks"].(map[string]any); cs == nil || cs["pre-sync"].(map[string]any)["state"] != "passed" || cs["post-sync"].(map[string]any)["state"] != "failed" {
		t.Fatalf("history checks: %v", row)
	}
	mu.Lock()
	defer mu.Unlock()
	var notes []string
	for _, q := range calls["/chat"] {
		notes = append(notes, q.Headers["X-MyDC-Event"])
	}
	if s := strings.Join(notes, ","); !strings.Contains(s, "cd.approved") || !strings.Contains(s, "cd.paused") {
		t.Fatalf("notices: %s", s)
	}
}

// Pre-sync acts only on new events about the candidate still waiting, and
// not without the approver's ApproveCD.
func TestWebhookCDOldEvents(t *testing.T) {
	f, fake, clock := incidentFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	pre := 0
	fake.SetServiceResponder("shop", "php-shop", "web", func(q mydc.ServiceCallRequest) mydc.ServiceResponse {
		mu.Lock()
		defer mu.Unlock()
		pre++
		return mydc.ServiceResponse{Status: 200, ContentType: "application/json", Body: []byte(`{"decision":"pass"}`)}
	})
	calls := func() int { mu.Lock(); defer mu.Unlock(); return pre }
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "mydc-autofix", "a1b2c3d4-0000-4000-8000-0000000000a3", true, true)
	fakeLogin(t, f, "alice")
	if code, out := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "pre", "tenant": "shop", "kind": "internal",
		"target": map[string]any{"app": "php-shop", "service": "web", "port": 8080, "path": "/pre"}, "role": "decide"}); code != 201 {
		t.Fatalf("webhook: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "cd", "scope": map[string]any{"tenant": "shop", "app": "php-shop"},
		"webhook": "pre", "kind": "pre-sync"}); code != 201 {
		t.Fatalf("link: %d %v", code, out)
	}
	doc := phpShopDoc(t, f)
	approvals := func() int {
		n := 0
		for _, e := range fake.Journal() {
			if e.Action == mydc.ActionApproveAppCD {
				n++
			}
		}
		return n
	}

	// Waiting before the first read: a backlog, left to a person.
	fake.SetCDCandidate("shop", "php-shop", "c0ffee1", strings.Replace(doc, "php-shop:1.4.2", "php-shop:1.5.0", 1))
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	if calls() != 0 || approvals() != 0 {
		t.Fatalf("first read: %d calls, %d approvals", calls(), approvals())
	}
	_, cd := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd", nil)
	id := cd["cd"].(map[string]any)["candidateDigest"].(string)

	// Older than the recent window, though about the waiting candidate.
	fake.AddEvent(mydc.FixtureEvent{Time: clock.Load() - 3600, Scope: "app", Tenant: "shop", App: "php-shop", Kind: mydc.EventCDApprovalRequired,
		CD: &mydc.CDEvent{CandidateID: id, Commit: "c0ffee1"}})
	// New, but about a candidate that is not the waiting one.
	fake.AddEvent(mydc.FixtureEvent{Time: clock.Load(), Scope: "app", Tenant: "shop", App: "php-shop", Kind: mydc.EventCDApprovalRequired,
		CD: &mydc.CDEvent{CandidateID: strings.Repeat("ab", 32), Commit: "dead000"}})
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	if calls() != 0 || approvals() != 0 {
		t.Fatalf("old or stale: %d calls, %d approvals", calls(), approvals())
	}

	// The automation account is no approver: the webhook is not called.
	approver := func(method string) {
		t.Helper()
		if code, out := f.do(method, "/api/v1/t/shop/apps/php-shop/cd/approvers", map[string]any{"opId": newOpID(), "userId": "u-mydc-autofix"}); opState(t, code, out) != "applied" {
			t.Fatalf("%s approver: %d %v", method, code, out)
		}
	}
	approver("DELETE")
	fake.AddEvent(mydc.FixtureEvent{Time: clock.Load(), Scope: "app", Tenant: "shop", App: "php-shop", Kind: mydc.EventCDApprovalRequired,
		CD: &mydc.CDEvent{CandidateID: id, Commit: "c0ffee1"}})
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	_, cd = f.do("GET", "/api/v1/t/shop/apps/php-shop/cd", nil)
	if w, _ := cd["webhook"].(map[string]any); calls() != 0 || w == nil || w["state"] != "failed" || !strings.Contains(fmt.Sprint(w["reason"]), "웹훅을 부르지 않았어요") {
		t.Fatalf("denied: %d calls, %v", calls(), cd["webhook"])
	}
	approver("POST")

	// A new event about the waiting candidate is checked and approved.
	fake.AddEvent(mydc.FixtureEvent{Time: clock.Load(), Scope: "app", Tenant: "shop", App: "php-shop", Kind: mydc.EventCDApprovalRequired,
		CD: &mydc.CDEvent{CandidateID: id, Commit: "c0ffee1"}})
	f.srv.watchOnce(ctx)
	f.srv.hooks.wg.Wait()
	if calls() != 1 || approvals() != 1 {
		t.Fatalf("fresh: %d calls, %d approvals", calls(), approvals())
	}
}
