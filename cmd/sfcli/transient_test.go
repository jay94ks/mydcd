// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestTransientOnlyCoversElectionAndLostReplies(t *testing.T) {
	for code, want := range map[string]bool{"not-leader": true, "unavailable": true, "unknown": true, "denied": false, "invalid": false, "transport": false} {
		if got := transient(&userauth.Error{Code: code}); got != want {
			t.Fatalf("%s: transient=%v want %v", code, got, want)
		}
	}
	if transient(errors.New("not-leader")) || transient(nil) {
		t.Fatal("an untyped or nil error is not a transient refusal")
	}
}

func shortTransientPause(t *testing.T) {
	old := transientPause
	transientPause = time.Millisecond
	t.Cleanup(func() { transientPause = old })
}

func TestSettleSendAsksAgainAcrossALeaderChange(t *testing.T) {
	shortTransientPause(t)
	firsts, agains := 0, 0
	reply, err := settleSend(context.Background(),
		func() (userauth.Reply, error) { firsts++; return userauth.Reply{}, &userauth.Error{Code: "not-leader"} },
		func() (userauth.Reply, error) {
			agains++
			if agains < 3 {
				return userauth.Reply{}, &userauth.Error{Code: "unavailable"}
			}
			return userauth.Reply{Found: true}, nil
		})
	if err != nil || !reply.Found || firsts != 1 || agains != 3 {
		t.Fatalf("reply=%+v err=%v first=%d again=%d", reply, err, firsts, agains)
	}
}

func TestSettleSendStopsOnFinalRefusalOrDeadline(t *testing.T) {
	shortTransientPause(t)
	agains := 0
	_, err := settleSend(context.Background(),
		func() (userauth.Reply, error) { return userauth.Reply{}, &userauth.Error{Code: "denied"} },
		func() (userauth.Reply, error) { agains++; return userauth.Reply{}, nil })
	var denied *userauth.Error
	if agains != 0 || !errors.As(err, &denied) || denied.Code != "denied" {
		t.Fatalf("a final refusal was retried: again=%d err=%v", agains, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = settleSend(ctx,
		func() (userauth.Reply, error) { return userauth.Reply{}, &userauth.Error{Code: "not-leader"} },
		func() (userauth.Reply, error) { agains++; return userauth.Reply{}, nil })
	if agains != 0 || !transient(err) {
		t.Fatalf("an ended context kept retrying: again=%d err=%v", agains, err)
	}
}

func TestFollowKeepsWaitingAcrossALeaderChange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	shortTransientPause(t)
	var stderr bytes.Buffer
	c := &cli.Context{Ctx: context.Background(), Out: &bytes.Buffer{}, Err: &stderr}
	calls := 0
	st, line, err := (&globals{}).follow(c, "abcd", func(*cli.Context) (cli.State, string, error) {
		calls++
		if calls < 3 {
			return "", "", &userauth.Error{Code: "not-leader"}
		}
		return cli.Done, "deleted", nil
	})
	if err != nil || st != cli.Done || line != "deleted" || calls != 3 {
		t.Fatalf("st=%s line=%q err=%v calls=%d", st, line, err, calls)
	}
	if _, _, err = (&globals{}).follow(c, "abcd", func(*cli.Context) (cli.State, string, error) {
		return "", "", &userauth.Error{Code: "denied"}
	}); err == nil || transient(err) {
		t.Fatalf("a final refusal must end waiting: %v", err)
	}
}
