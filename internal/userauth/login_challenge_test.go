// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestLoginChallengeExplicitLeaderRefusal(t *testing.T) {
	a, b := sfcp.Peer{ID: "a"}, sfcp.Peer{ID: "b"}
	refused := &Error{Code: "not-leader", Phase: sfcp.Completed}
	for _, exhaust := range []bool{false, true} {
		calls := 0
		reply, selected, err := retryLoginChallenge(context.Background(), a, func(_ context.Context, target sfcp.Peer) (Reply, sfcp.Peer, error) {
			calls++
			if calls == 1 && target != a || calls > 1 && target != b {
				t.Fatal("retry discarded the authenticated selected peer", target)
			}
			if !exhaust && calls == 2 {
				return Reply{Code: "ok", Data: []byte("{}")}, b, nil
			}
			return Reply{Code: "not-leader"}, b, fmt.Errorf("challenge: %w", refused)
		})
		if exhaust {
			if calls != 5 || !errors.Is(err, refused) || reply.Code != "not-leader" || selected != b {
				t.Fatal("leader refusal must terminate with its original error", calls, err)
			}
		} else if calls != 2 || err != nil || len(reply.Data) == 0 || selected != b {
			t.Fatal("explicit refusal did not preserve ticket issuer", calls, err)
		}
	}
}

func TestLoginChallengeDoesNotRetryUncertainOrCredentialFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply Reply
		err   error
	}{
		{"transport-not-sent", Reply{}, &Error{Code: "transport", Phase: sfcp.NotSent}},
		{"transport-unknown", Reply{}, &Error{Code: "transport", Phase: sfcp.Unknown}},
		{"unconfirmed-refusal", Reply{Code: "not-leader"}, &Error{Code: "not-leader", Phase: sfcp.Unknown}},
		{"denied", Reply{Code: "denied"}, &Error{Code: "denied", Phase: sfcp.Completed}},
		{"issuer-disabled", Reply{Code: "not-session-issuer"}, &Error{Code: "not-session-issuer", Phase: sfcp.Completed}},
		{"frame", Reply{}, sfcp.ErrFrame},
		{"contradictory-ticket", Reply{Code: "not-leader", Data: []byte("{}")}, &Error{Code: "not-leader", Phase: sfcp.Completed}},
		{"untyped-refusal", Reply{Code: "not-leader"}, errors.New("not-leader")},
		{"contradictory-code", Reply{Code: "unknown"}, &Error{Code: "not-leader", Phase: sfcp.Completed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, _, err := retryLoginChallenge(context.Background(), sfcp.Peer{}, func(context.Context, sfcp.Peer) (Reply, sfcp.Peer, error) {
				calls++
				return tc.reply, sfcp.Peer{}, tc.err
			})
			if calls != 1 || err != tc.err {
				t.Fatal("replayed a terminal challenge outcome", calls, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, _, err := retryLoginChallenge(ctx, sfcp.Peer{}, func(context.Context, sfcp.Peer) (Reply, sfcp.Peer, error) {
		calls++
		cancel()
		return Reply{Code: "not-leader"}, sfcp.Peer{}, &Error{Code: "not-leader", Phase: sfcp.Completed}
	})
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation allowed another attempt", calls, err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, _, err = retryLoginChallenge(ctx, sfcp.Peer{}, func(context.Context, sfcp.Peer) (Reply, sfcp.Peer, error) {
		t.Fatal("expired challenge dialed")
		return Reply{}, sfcp.Peer{}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
