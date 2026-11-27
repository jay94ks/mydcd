// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/web/provlog"
)

func TestReadSSE(t *testing.T) {
	stream := "event: state\ndata: {\"enabled\":true}\n\n" +
		"id: 3\nevent: entry\ndata: {\"seq\":3,\"provider\":\"dns:hostinger\",\"op\":\"GetZone\",\"level\":\"info\"}\n\n" +
		": ping\n\n" +
		"event: expired\ndata: {}\n\n"
	var got []provlog.Entry
	cur, expired, err := readSSE(strings.NewReader(stream), 1, func(e provlog.Entry) error { got = append(got, e); return nil }, io.Discard)
	if err != nil || !expired || cur != 3 || len(got) != 1 || got[0].Op != "GetZone" {
		t.Fatalf("cur %d expired %v err %v got %+v", cur, expired, err, got)
	}
	_, expired, err = readSSE(strings.NewReader("event: entry\n"), 0, func(provlog.Entry) error { return nil }, io.Discard)
	if expired || err == nil {
		t.Fatal("a dropped stream must be an error so the tool reconnects")
	}
}

func TestToolPollsAllPagesAndSummarizes(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Query().Get("after") == "0" {
			io.WriteString(w, `{"page":{"entries":[{"seq":1,"provider":"dns:hostinger","op":"Apply","level":"warn","http":{"method":"PUT","url":"/x","status":422,"durationMs":10,"response":"bad"}}],"next":1,"more":true},"state":{"enabled":true}}`)
			return
		}
		io.WriteString(w, `{"page":{"entries":[{"seq":2,"provider":"dns:hostinger","op":"Apply","level":"info","http":{"method":"PUT","url":"/x","status":200,"durationMs":30}}],"next":2,"more":false},"state":{"enabled":true}}`)
	}))
	defer srv.Close()
	var out, errb bytes.Buffer
	env := func(k string) string {
		if k == "SFC_WEB_DIAG_TOKEN" {
			return "mpl_x"
		}
		return ""
	}
	if code := providerLogTool([]string{"-url", srv.URL, "-format", "summary"}, &out, &errb, env); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	s := out.String()
	if !strings.Contains(s, "2 entries") || !strings.Contains(s, "200×1 422×1") || !strings.Contains(s, "response: bad") {
		t.Fatalf("summary:\n%s", s)
	}
	if len(auth) != 2 || auth[0] != "Bearer mpl_x" {
		t.Fatalf("auth %v", auth)
	}
	if code := providerLogTool([]string{"-url", srv.URL}, &out, &errb, func(string) string { return "" }); code != 2 {
		t.Fatal("no token must fail")
	}
}

func TestTextLine(t *testing.T) {
	e := provlog.Entry{Seq: 9, At: time.Unix(0, 0), Level: "error", Provider: "acme:letsencrypt", Op: "Finalize", Error: "boom"}
	if s := textLine(e); !strings.Contains(s, "acme:letsencrypt Finalize") || !strings.Contains(s, "error=boom") {
		t.Fatal(s)
	}
}
