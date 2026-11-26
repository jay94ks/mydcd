// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func TestDeliveryReadAuthorityFailureDoesNotDispatchPolicyCleanupForUncertainty(t *testing.T) {
	for _, tc := range []struct {
		err       error
		uncertain bool
	}{
		{context.Canceled, true}, {context.DeadlineExceeded, true},
		{raft.ErrNotLeader, true}, {raft.ErrLeadershipLost, true},
		{raft.ErrRaftShutdown, true}, {raft.ErrEnqueueTimeout, true},
		{cluster.ErrRecovering, true}, {errNoAppLeader, true},
		{errAppLeaderPeerUnavailable, true}, {mydcp.ErrAdmission, false},
		{&cluster.ManagementError{Code: "not-leader"}, true},
		{&cluster.ManagementError{Code: "unavailable"}, true},
		{&cluster.ManagementError{Code: "unknown"}, true},
		{&cluster.ManagementError{Code: "transport"}, true},
		{access.ErrDenied, false}, {control.ErrCatalog, false},
		{&cluster.ManagementError{Code: "denied"}, false},
		{&cluster.ManagementError{Code: "invalid"}, false},
		{deployment.ErrSource, false},
	} {
		calls := 0
		wrapped := fmt.Errorf("source authorization: %w", tc.err)
		cleanup := errors.New("original cleanup outcome")
		err := handleDeliveryReadAuthorityFailure(wrapped, func() error { calls++; return cleanup })
		if !errors.Is(err, tc.err) || tc.uncertain && (calls != 0 || errors.Is(err, cleanup)) || !tc.uncertain && (calls != 1 || !errors.Is(err, cleanup)) {
			t.Fatal("read uncertainty became cleanup or definitive rejection lost", tc.err, calls, err)
		}
	}
	if !errors.Is(errAppLeaderPeerUnavailable, mydcp.ErrAdmission) {
		t.Fatal("qualified transport failure lost admission compatibility")
	}
}

// Actual N1/MYDCP/Raft/bbolt metadata, using the existing fixture. The source
// bytes and authority errors are injected; no Git/Docker readiness is claimed.
func verifyRealDeliveryAuthorityUncertainty(t *testing.T, ctx context.Context, r *Runtime, pause func(uint64)) {
	t.Helper()
	permit := func() control.AppDeliveryPermit {
		t.Helper()
		p, err := r.deliveryPermit(ctx, "tenant", "app", nil)
		if err != nil {
			t.Fatal("current real source permit", err)
		}
		return p
	}
	progress := func(p control.AppDeliveryPermit, q control.AppDeliveryProgress) {
		t.Helper()
		if err := r.deliveryProgress(ctx, p, q); err != nil {
			t.Fatal("original source metadata progress", err)
		}
	}
	initial := permit()
	progress(initial, control.AppDeliveryProgress{Action: "fetch"})
	p := permit()
	if p.Ticket == nil {
		t.Fatal("original fetch absent")
	}
	ticket := *p.Ticket
	body := bytes.Repeat([]byte("x"), deployment.ArtifactPartBytes+17)
	digest := sha256.Sum256(body)
	input := control.AppDeliveryInput{Ticket: ticket, Upload: "original-source", Commit: strings.Repeat("a", 40)}
	begin := control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: p.Scope.Deployment, ID: input.Upload, Length: len(body), Digest: digest}
	progress(p, control.AppDeliveryProgress{Action: "input", Ticket: &ticket, Input: &input, Begin: &begin})
	part := control.AppUploadPart{Tenant: "tenant", ID: input.Upload, Index: 0, Data: body[:deployment.ArtifactPartBytes]}
	// The input registration changes its semantic binding. Obtain that exact
	// target, while keeping an earlier incidental module-root coordinate.
	inputPermit := permit()
	inputPermit.RootRevision = p.RootRevision
	progress(inputPermit, control.AppDeliveryProgress{Action: "part", Ticket: &ticket, Part: &part})
	before, err := r.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	// An unrelated Apps root change cannot block the same signed ticket part.
	// A truly older CD revision still cannot begin another fetch or alter it.
	// Do not resend the exact accepted fetch: that must return its original
	// Applied receipt. A current root cannot authorize an older typed revision.
	staleTarget := initial
	staleTarget.RootRevision = before.State.Object(control.AppsKey).Revision
	if err = r.deliveryProgress(ctx, staleTarget, control.AppDeliveryProgress{Action: "fetch"}); err == nil {
		t.Fatal("current root authorized an old CD revision")
	}
	afterStale, err := r.Engine().Read(ctx, true)
	if err != nil || afterStale.State.Object(control.AppsKey) != before.State.Object(control.AppsKey) {
		t.Fatal("stale root rejection changed original partial input", err)
	}
	for _, cause := range []error{raft.ErrLeadershipLost, errAppLeaderPeerUnavailable, &cluster.ManagementError{Code: "unavailable"}, &cluster.ManagementError{Code: "transport"}} {
		err := handleDeliveryReadAuthorityFailure(cause, func() error {
			return r.deliverySourceFailure(ctx, "tenant", "app", ticket, "policy")
		})
		if !errors.Is(err, cause) {
			t.Fatal("original read failure was lost", err)
		}
		after, err := r.Engine().Read(ctx, true)
		if err != nil || after.State.Object(control.AppsKey) != before.State.Object(control.AppsKey) {
			t.Fatal("transient failure changed the original shared input", err)
		}
		same := permit()
		if same.Ticket == nil || *same.Ticket != ticket || same.Input == nil || *same.Input != input || same.Upload == nil || same.Upload.Digest != digest || len(same.Upload.Missing) != 1 || same.Upload.Missing[0] != 1 {
			t.Fatal("original ticket/commit/hash/first part was discarded")
		}
	}
	// Recovery continues the same fetch and exact missing part, not a new
	// source sequence or an app operation, after a fresh real permit.
	part.Index, part.Data = 1, body[deployment.ArtifactPartBytes:]
	progress(permit(), control.AppDeliveryProgress{Action: "part", Ticket: &ticket, Part: &part})
	complete := permit()
	if complete.Ticket == nil || *complete.Ticket != ticket || complete.Upload == nil || len(complete.Upload.Missing) != 0 || complete.Upload.Digest != digest {
		t.Fatal("authority recovery did not preserve the original upload")
	}
	pause(complete.Revision)
	_, denied := r.deliveryPermit(ctx, "tenant", "app", &ticket)
	if denied == nil || deliveryReadAuthorityUncertain(denied) {
		t.Fatal("explicit paused source was treated as a transient read", denied)
	}
	if err = handleDeliveryReadAuthorityFailure(denied, func() error {
		return r.deliverySourceFailure(ctx, "tenant", "app", ticket, "policy")
	}); !errors.Is(err, denied) {
		t.Fatal("original policy rejection disappeared", err)
	}
	final, err := r.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	apps, err := r.controlPolicy.Apps(final.State)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := apps.Delivery("tenant", "app")
	if _, pending := d.FetchTicket(); !ok || pending || d.SourceError() != "policy" {
		t.Fatal("definitive rejection did not settle its original ticket")
	}
	users, err := r.controlPolicy.Catalog(final.State)
	if err != nil {
		t.Fatal(err)
	}
	uploads, _, err := apps.Uploads(users, d.Principal(), "tenant", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, upload := range uploads {
		if upload.ID == input.Upload {
			t.Fatal("source cleanup retained its original partial input")
		}
	}
	t.Log("real metadata retained exact fetch/commit/hash/part across transient authority errors, then continued same ticket; explicit source pause still settled original input; no Git or native effect")
}
