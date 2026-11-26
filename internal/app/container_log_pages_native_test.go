// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Reuses the existing actual managed-app owner and rollback; this does not
// construct a separate observer or bypass the user/owner permit boundaries.
func verifyContainerLogPaging(t *testing.T, ctx context.Context, runtime *Runtime, user userauth.Client, peer mydcp.Peer, session access.Session) {
	t.Helper()
	query := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "logs", Tail: 10000, Stdout: true, Stderr: true, MaxBytes: containerops.MaxOutput}
	first, err := user.ObserveContainer(ctx, peer, session, "tenant", query)
	if err != nil || first.Container == nil {
		t.Fatal("initial paging native target", err)
	}
	target := first.Container.Target
	probe, err := runtime.workload.ProbeTarget(ctx, target.Instance, target.Generation, target.Revision)
	if err != nil || !probe.IPv4.IsValid() {
		t.Fatal("owned log fixture address", err)
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+net.JoinHostPort(probe.IPv4.String(), "8080")+"/logburst?marker=rq4-log-cursor", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("native log burst", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("native log fixture did not emit requested records")
	}
	first, err = user.ObserveContainer(ctx, peer, session, "tenant", query)
	if err != nil || first.Container == nil || first.Container.NextCursor == "" {
		t.Fatal("large log window did not expose next page", err)
	}
	var combined []byte
	page := *first.Container
	for i := 0; ; i++ {
		if i > 16 || page.Validate(query, target) != nil {
			t.Fatal("invalid/repeated actual log page")
		}
		combined = append(combined, page.Stdout...)
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
		next, err := user.ObserveContainer(ctx, peer, session, "tenant", query)
		if err != nil || next.Container == nil {
			t.Fatal("actual owner cursor continuation", err)
		}
		page = *next.Container
	}
	for i := 0; i < 32; i++ {
		if bytes.Count(combined, []byte(fmt.Sprintf("rq4-log-cursor-%03d:", i))) != 1 {
			t.Fatal("actual repeated timestamp log record lost/duplicated", i)
		}
	}
	query.Cursor = first.Container.NextCursor
	query.MaxBytes--
	_, err = user.ObserveContainer(ctx, peer, session, "tenant", query)
	var input *deployment.InputError
	if !errors.As(err, &input) || input.Code != "CURSOR_EXPIRED" {
		t.Fatal("remote owner cursor mismatch lost typed expiry", err)
	}
	if strings.Contains(string(combined), "private-db-value") {
		t.Fatal("raw fixture secret returned")
	}
}
