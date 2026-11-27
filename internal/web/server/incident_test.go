// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

func opSeq(prefix string) func() string {
	n := 0
	return func() string { n++; return fmt.Sprintf("%s-0000-4000-8000-%012d", prefix, n) }
}

// the web-added services, approve/reject with a reason, the
// per-app approver.
func TestCDLocalAndDecisions(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("cd15aaaa")
	fakeLogin(t, f, "alice")
	code, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/local", nil)
	if code != 200 || out["localRevision"] != 0.0 || len(out["gitServices"].([]any)) != 2 || len(out["services"].([]any)) != 0 {
		t.Fatalf("local: %d %v", code, out)
	}
	local := "services:\n  report:\n    image: registry.sfc.local/shop/report:1\n    x-sfc:\n      node: node-a\n    networks: [shop-net]\n"
	if code, out := f.do("PUT", "/api/v1/t/shop/apps/php-shop/cd/local", map[string]any{"opId": op(), "document": local}); opState(t, code, out) != "applied" {
		t.Fatalf("put local: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/local", nil); out["services"].([]any)[0] != "report" {
		t.Fatalf("local after: %v", out)
	}
	if code, out := f.do("PUT", "/api/v1/t/shop/apps/php-shop/cd/local", map[string]any{"opId": op(), "document": "services:\n  web:\n    image: x:1\n"}); opState(t, code, out) == "applied" {
		t.Fatalf("git service: %d %v", code, out)
	}

	// Approvers: grant bob (a viewer) approval of php-shop only.
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/approvers", map[string]any{"opId": op(), "user": "bob"}); opState(t, code, out) != "applied" {
		t.Fatalf("grant: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/approvers", nil); fmt.Sprint(out["approvers"]) != "[bob]" {
		t.Fatalf("approvers: %v", out)
	}
	cand := func() string {
		_, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd", nil)
		return out["cd"].(map[string]any)["candidateDigest"].(string)
	}
	fake.SetCDCandidate("shop", "php-shop", "c0ffee1", strings.Replace(phpShopDoc(t, f), "php-shop:1.4.2", "php-shop:1.5.0", 1))
	stale := strings.Repeat("0", 64)
	bobLogin(t, f)
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/candidate/approve", map[string]any{"opId": op(), "candidate": stale}); code != 409 || errCode(out) != "candidate-changed" {
		t.Fatalf("stale candidate: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/candidate/reject", map[string]any{"opId": op(), "candidate": cand(), "operation": "x"}); code != 400 {
		t.Fatalf("reject with operation: %d %v", code, out)
	}
	if code, out := f.send("POST", "/api/v1/t/shop/apps/php-shop/cd/candidate/reject", []byte(`{"opId":"`+op()+`","candidate":"`+cand()+`","reason":"a"}`),
		map[string]string{"X-SFC-Reason": "b"}); code != 400 {
		t.Fatalf("reason twice: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/candidate/reject", map[string]any{"opId": op(), "candidate": cand(), "reason": "웹훅 실패"}); opState(t, code, out) != "applied" {
		t.Fatalf("reject: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/approvers", map[string]any{"opId": op(), "user": "bob"}); opState(t, code, out) == "applied" {
		t.Fatalf("approver grants: %d %v", code, out)
	}
	fake.SetCDCandidate("shop", "php-shop", "c0ffee2", strings.Replace(phpShopDoc(t, f), "php-shop:1.4.2", "php-shop:1.5.1", 1))
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/candidate/approve", map[string]any{"opId": op(), "candidate": cand(), "reason": "검토 완료"}); opState(t, code, out) != "applied" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/events?tenant=shop&limit=1000", nil); !strings.Contains(fmt.Sprint(out["items"]), "검토 완료") {
		t.Fatalf("events lack the approval: %v", out)
	}
	fakeLogin(t, f, "alice")
	if code, out := f.do("DELETE", "/api/v1/t/shop/apps/php-shop/cd/approvers", map[string]any{"opId": op(), "user": "bob"}); opState(t, code, out) != "applied" {
		t.Fatalf("revoke: %d %v", code, out)
	}
}

// phpShopDoc is the fixture's php-shop app.yaml.
func phpShopDoc(*testing.T, *fixture) string {
	return `name: php-shop
x-sfc:
  lifecycle:
    scripts:
      ready:
        ref: {name: http-ready, revision: 2}
services:
  web:
    image: registry.sfc.local/shop/php-shop:1.4.2
    x-sfc:
      node: node-a
      lifecycle:
        checks:
          - id: ready
            phase: readiness
            script: ready
    networks: [shop-net]
  db:
    image: mysql:8.4
    x-sfc:
      node: node-b
    networks: [shop-net]
    volumes:
      - mysql-data:/var/lib/mysql
`
}

// send is a raw request with extra headers.
func (f *fixture) send(method, path string, body []byte, hdr map[string]string) (int, map[string]any) {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
	req.Header.Set("X-SFC-Web", "1")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// storedZip is a zip with uncompressed entries (its size is its content).
func storedZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// a service call answers a code, never an error, for a failed call.
func TestServiceCall(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	call := map[string]any{"service": "web", "port": 8080, "path": "/hooks/deploy", "text": `{"v":1}`, "headers": map[string]string{"Content-Type": "application/json"}}
	code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/call", call)
	if code != 200 || out["status"] != 200.0 || out["task"] == nil {
		t.Fatalf("call: %d %v", code, out)
	}
	fake.SetServiceResponder("shop", "php-shop", "web", func(sfc.ServiceCallRequest) sfc.ServiceResponse { return sfc.ServiceResponse{Refused: true} })
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/call", call); code != 200 || out["code"] != sfc.ServiceCallRefused {
		t.Fatalf("refused: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/call", map[string]any{"service": "web", "port": 8080, "path": "/x", "headers": map[string]string{"Authorization": "x"}}); code != 422 {
		t.Fatalf("header: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/call", map[string]any{"service": "web", "port": 8080, "path": "http://x/"}); code != 422 {
		t.Fatalf("path: %d %v", code, out)
	}
	bobLogin(t, f)
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/call", call); code != 403 {
		t.Fatalf("viewer: %d %v", code, out)
	}
}

// the account scope and display-only op reasons.
func TestAccountScopeAndReason(t *testing.T) {
	f, _ := newFakeFixture(t)
	op := opSeq("cd09aaaa")
	fakeLogin(t, f, "alice")
	if code, out := f.do("GET", "/api/v1/users/u-alice/scope", nil); code != 200 || out["revision"] == 0.0 || len(out["actions"].([]any)) != 0 || out["keyOnly"] != false {
		t.Fatalf("own scope: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/users/u-bob/scope", map[string]any{"opId": op(), "expected": 1, "add": []string{"restart-task"}}); code != 403 {
		t.Fatalf("non-admin scope: %d %v", code, out)
	}

	// A reason header goes with the op and is part of its digest.
	id := op()
	put := func(id, reason string) (int, map[string]any) {
		hdr := map[string]string{"Content-Type": "application/json"}
		if reason != "" {
			hdr["X-SFC-Reason"], hdr["X-SFC-Incident"] = url.PathEscape(reason), "inc-7"
		}
		return f.send("POST", "/api/v1/t/shop/apps/php-shop/cd/pause", []byte(`{"opId":"`+id+`"}`), hdr)
	}
	code, out := put(id, "자동 대응")
	if opState(t, code, out) != "applied" || out["op"].(map[string]any)["reason"].(map[string]any)["reason"] != "자동 대응" {
		t.Fatalf("reasoned op: %d %v", code, out)
	}
	if code, out := put(id, ""); code != 409 {
		t.Fatalf("same opId without the reason: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/ops/"+id+"/reason", nil); code != 200 || out["found"] != true || out["reason"] != "자동 대응" || out["incident"] != "inc-7" {
		t.Fatalf("reason: %d %v", code, out)
	}
	if code, out := f.send("POST", "/api/v1/t/shop/apps/php-shop/cd/pause", []byte(`{"opId":"`+op()+`"}`),
		map[string]string{"X-SFC-Reason": url.PathEscape(strings.Repeat("가", 513))}); code != 400 {
		t.Fatalf("long reason: %d %v", code, out)
	}

	fakeLogin(t, f, "admin")
	revision := func() any {
		_, out := f.do("GET", "/api/v1/users/u-bob/scope", nil)
		return out["revision"]
	}
	patch := func(body map[string]any) (int, map[string]any) {
		body["opId"] = op()
		return f.do("PATCH", "/api/v1/users/u-bob/scope", body)
	}
	rev := revision()
	for _, bad := range []map[string]any{
		{"expected": rev},
		{"expected": rev, "unlimited": true, "add": []string{"restart-task"}},
		{"add": []string{"restart-task"}},
	} {
		if code, out := patch(bad); code != 422 {
			t.Fatalf("bad change %v: %d %v", bad, code, out)
		}
	}
	if code, out := patch(map[string]any{"expected": rev.(float64) + 1, "add": []string{"restart-task"}}); code != 409 || errCode(out) != "stale" {
		t.Fatalf("stale: %d %v", code, out)
	}
	if code, out := patch(map[string]any{"expected": rev, "remove": []string{"restart-task"}}); code != 422 || errCode(out) != "no-such-action" {
		t.Fatalf("remove a missing action: %d %v", code, out)
	}
	if code, out := patch(map[string]any{"expected": rev, "add": []string{"restart-task", "pause-app-cd"}, "keyOnly": true}); opState(t, code, out) != "applied" {
		t.Fatalf("scope: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/users/u-bob/scope", nil); code != 200 || out["keyOnly"] != true || len(out["actions"].([]any)) != 2 || out["revision"] == rev {
		t.Fatalf("scope read: %d %v", code, out)
	}
	if code, out := patch(map[string]any{"expected": revision(), "add": []string{"restart-task"}}); code != 422 || errCode(out) != "exists" {
		t.Fatalf("add an action it has: %d %v", code, out)
	}
	if code, out := patch(map[string]any{"expected": revision(), "remove": []string{"pause-app-cd"}}); opState(t, code, out) != "applied" {
		t.Fatalf("remove one: %d %v", code, out)
	}
	if code, out := patch(map[string]any{"expected": revision(), "unlimited": true, "keyOnly": false}); opState(t, code, out) != "applied" {
		t.Fatalf("drop scope: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/users/u-bob/scope", nil); len(out["actions"].([]any)) != 0 || out["keyOnly"] != false {
		t.Fatalf("unlimited: %v", out)
	}
}

// cordon, tunnel reconnect, the image prune plan.
func TestIncidentActions(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("cd11aaaa")
	fakeLogin(t, f, "alice")
	if code, out := f.do("POST", "/api/v1/nodes/node-a/cordon", map[string]any{"opId": op()}); code != 403 {
		t.Fatalf("non-admin cordon: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/t/payments/networks/payments-net/tunnels", nil); code != 200 || len(out["items"].([]any)) == 0 {
		t.Fatalf("tunnels: %d %v", code, out)
	}
	fakeLogin(t, f, "admin")
	if code, out := f.do("POST", "/api/v1/nodes/node-a/cordon", map[string]any{"opId": op(), "reason": "디스크 경보"}); opState(t, code, out) != "applied" {
		t.Fatalf("cordon: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/cordon", map[string]any{"opId": op()}); code != 409 {
		t.Fatalf("cordon again: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/nodes", nil); !strings.Contains(fmt.Sprint(out["items"]), "cordonReason:디스크 경보") {
		t.Fatalf("member lacks cordon: %v", out)
	}
	// who and when, the time as RFC 3339.
	_, nodes := f.do("GET", "/api/v1/nodes", nil)
	for _, it := range nodes["items"].([]any) {
		if n := it.(map[string]any); n["id"] == "node-a" {
			at, _ := n["cordonedAt"].(string)
			if _, err := time.Parse(time.RFC3339, at); err != nil || n["cordonedBy"] != "admin" {
				t.Fatalf("cordoned by/at: %v", n)
			}
		}
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/uncordon", map[string]any{"opId": op(), "reason": "x"}); code != 422 {
		t.Fatalf("uncordon reason: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/uncordon", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("uncordon: %d %v", code, out)
	}

	rec := map[string]any{"opId": op(), "from": "node-c", "to": "node-a"}
	if code, out := f.do("POST", "/api/v1/t/payments/networks/payments-net/tunnels/reconnect", rec); code != 409 || errCode(out) != "not-down" {
		t.Fatalf("reconnect up: %d %v", code, out)
	}
	fake.SetMeshLinkDown("node-c", "node-a", true)
	rec["opId"] = op()
	o := rec["opId"].(string)
	if code, out := f.do("POST", "/api/v1/t/payments/networks/payments-net/tunnels/reconnect", rec); opState(t, code, out) != "applied" {
		t.Fatalf("reconnect: %d %v", code, out)
	}
	var change control.TunnelChange
	userPayload(t, f, "u-admin", o, &change)
	if change.Operation != "op-"+o || change.Plan.Node != "node-c" || change.Plan.Peer != "node-a" || change.Plan.PairID != "node-a/node-c" {
		t.Fatalf("payload: %+v", change)
	}
	if code, out := f.do("GET", "/api/v1/t/payments/networks/payments-net/tunnels", nil); code != 200 || !strings.Contains(fmt.Sprint(out["items"]), "pairId:node-a/node-c") {
		t.Fatalf("tunnels: %d %v", code, out)
	}
	fake.FinishTunnelReconnects()
	if code, st := f.do("GET", "/api/v1/tunnel-reconnects/op-"+o, nil); code != 200 || st["node"] != "node-c" || st["result"] != "reconnected" {
		t.Fatalf("status: %d %v", code, st)
	}
	if code, _ := f.do("GET", "/api/v1/tunnel-reconnects/op-nothing", nil); code != 404 {
		t.Fatalf("unknown status: %d", code)
	}
	// the node route: the same contract, the link is up again
	if code, out := f.do("POST", "/api/v1/nodes/node-c/tunnels/node-a/reconnect", map[string]any{"opId": op()}); code != 409 || errCode(out) != "not-down" {
		t.Fatalf("node route up: %d %v", code, out)
	}
	fakeLogin(t, f, "alice")
	if code, out := f.do("POST", "/api/v1/nodes/node-c/tunnels/node-a/reconnect", map[string]any{"opId": op()}); code != 403 {
		t.Fatalf("non-admin reconnect: %d %v", code, out)
	}
	fakeLogin(t, f, "admin")

	code, plan := f.do("GET", "/api/v1/nodes/node-a/image-prune-plan", nil)
	if code != 200 || len(plan["images"].([]any)) == 0 || len(plan["plan"].(string)) != 64 {
		t.Fatalf("plan: %d %v", code, plan)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/image-prune", map[string]any{"opId": op(), "plan": strings.Repeat("ab", 32)}); code != 409 {
		t.Fatalf("stale plan: %d %v", code, out)
	}
	lastOp := op()
	if code, out := f.do("POST", "/api/v1/nodes/node-a/image-prune", map[string]any{"opId": lastOp, "plan": plan["plan"]}); opState(t, code, out) != "applied" {
		t.Fatalf("prune: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/nodes/node-a/image-prune-plan", nil); len(out["images"].([]any)) != 0 || out["remaining"] != 0.0 {
		t.Fatalf("after prune: %v", out)
	}
	if code, out := f.do("GET", "/api/v1/image-prunes/op-"+lastOp, nil); code != 200 || out["state"] != "done" || len(out["parts"].([]any)) != len(plan["images"].([]any)) {
		t.Fatalf("prune status: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/image-prunes/op-nothing", nil); code != 404 {
		t.Fatalf("unknown prune: %d %v", code, out)
	}
}

// a zip over 8 MiB in web chunks of 128 parts of 32 KiB.
func TestBuildZipChunkedUpload(t *testing.T) {
	f, _ := newFakeFixture(t)
	op := opSeq("cd47aaaa")
	fakeLogin(t, f, "alice")
	zip := storedZip(t, map[string]string{"Dockerfile": "FROM docker.io/library/busybox:1.36\nCOPY big /big\n", "big": strings.Repeat("청크-올리기-시험-", 1<<18)})
	if len(zip) <= maxZipChunkBytes {
		t.Fatalf("zip of %d bytes is one chunk", len(zip))
	}
	sum := sha256.Sum256(zip)
	begin := op()
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/zip-uploads", map[string]any{"opId": begin, "length": len(zip), "digest": hex.EncodeToString(sum[:])}); opState(t, code, out) != "applied" {
		t.Fatalf("begin: %d %v", code, out)
	}
	base := "/api/v1/t/shop/build-contexts/worker/zip-uploads/web-" + begin
	code, view := f.do("GET", base, nil)
	chunks := int(view["chunks"].(float64))
	cb := int(view["chunkBytes"].(float64))
	if code != 200 || chunks < 2 || cb != 4<<20 || view["partBytes"] != float64(32<<10) || len(view["missingChunks"].([]any)) != chunks || view["complete"] != false {
		t.Fatalf("view: %d %v", code, view)
	}
	if code, out := f.do("POST", base+"/finish", map[string]any{"opId": op()}); code != 409 || errCode(out) != "incomplete" {
		t.Fatalf("finish early: %d %v", code, out)
	}
	put := func(n int, data []byte) (int, map[string]any) {
		return f.send("PUT", fmt.Sprintf("%s/chunks/%d", base, n), data, nil)
	}
	chunk := func(n int) []byte { return zip[n*cb : min(len(zip), (n+1)*cb)] }
	if code, out := put(0, chunk(0)[1:]); code != 422 {
		t.Fatalf("short chunk: %d %v", code, out)
	}
	// last chunk first, then the rest; chunk 0 twice (a lost answer)
	for _, n := range append([]int{chunks - 1}, func() []int {
		var o []int
		for i := 0; i < chunks-1; i++ {
			o = append(o, i)
		}
		return o
	}()...) {
		if code, out := put(n, chunk(n)); code != 200 {
			t.Fatalf("chunk %d: %d %v", n, code, out)
		}
	}
	if code, out := put(0, chunk(0)); code != 200 || out["complete"] != true {
		t.Fatalf("chunk again: %d %v", code, out)
	}
	if code, out := f.do("POST", base+"/finish", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("finish: %d %v", code, out)
	}
	if code, _ := f.do("GET", base, nil); code != 404 {
		t.Fatalf("upload kept after finish: %d", code)
	}
	assertNowhere(t, f, "청크-올리기-시험-청크-올리기-시험-")

	// abort; a wrong digest is refused at the last part
	bad := op()
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/zip-uploads", map[string]any{"opId": op(), "length": len(zip), "digest": strings.Repeat("00", 32)}); code != 422 {
		t.Fatalf("zero digest: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/zip-uploads", map[string]any{"opId": bad, "length": len(zip), "digest": strings.Repeat("ab", 32)}); opState(t, code, out) != "applied" {
		t.Fatalf("begin bad: %d %v", code, out)
	}
	badBase := "/api/v1/t/shop/build-contexts/worker/zip-uploads/web-" + bad
	for n := 0; n < chunks; n++ {
		code, out := f.send("PUT", fmt.Sprintf("%s/chunks/%d", badBase, n), chunk(n), nil)
		if n < chunks-1 && code != 200 || n == chunks-1 && (code != 422 || errCode(out) != "part-refused") {
			t.Fatalf("bad digest chunk %d: %d %v", n, code, out)
		}
	}
	if code, out := f.do("DELETE", badBase, map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("abort: %d %v", code, out)
	}
	// not a zip: every part is taken, the seal refuses it
	junk := []byte(strings.Repeat("not a zip ", 100))
	js := sha256.Sum256(junk)
	jop := op()
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/zip-uploads", map[string]any{"opId": jop, "length": len(junk), "digest": hex.EncodeToString(js[:])}); opState(t, code, out) != "applied" {
		t.Fatalf("begin junk: %d %v", code, out)
	}
	jBase := "/api/v1/t/shop/build-contexts/worker/zip-uploads/web-" + jop
	if code, out := f.send("PUT", jBase+"/chunks/0", junk, nil); code != 200 || out["complete"] != true {
		t.Fatalf("junk chunk: %d %v", code, out)
	}
	if code, out := f.do("POST", jBase+"/finish", map[string]any{"opId": op()}); code != 422 || errCode(out) != "part-refused" {
		t.Fatalf("junk finish: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/build-contexts/cron/zip-uploads", map[string]any{"opId": op(), "length": 10, "digest": strings.Repeat("ab", 32)}); code != 409 {
		t.Fatalf("inline context: %d", code)
	}
}
