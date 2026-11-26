// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestParallelRouteNativeReadsStartBothAndJoinCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 2)
	exited := make(chan string, 2)
	finished := make(chan [2]routeNativeReadback, 1)
	callback := func(name string) func(context.Context) (routeFlowReply, error) {
		return func(call context.Context) (routeFlowReply, error) {
			started <- name
			<-call.Done()
			exited <- name
			return routeFlowReply{}, call.Err()
		}
	}
	go func() { finished <- parallelRouteNativeReadbacks(ctx, callback("local"), callback("peer")) }()
	limit := time.After(time.Second)
	for range 2 {
		select {
		case <-started:
		case <-limit:
			t.Fatal("second native query did not start independently")
		}
	}
	cancel()
	select {
	case results := <-finished:
		if len(exited) != 2 {
			t.Fatal("native read escaped join")
		}
		for _, r := range results {
			if !errors.Is(r.err, context.Canceled) || r.completed.IsZero() {
				t.Fatal("cancellation/context lost")
			}
		}
	case <-time.After(time.Second):
		t.Fatal("canceled pair did not join")
	}
}
func TestParallelRouteNativeReadsPreserveBothOutcomesAndJoinFailure(t *testing.T) {
	release := make(chan struct{})
	peerFailed := make(chan struct{})
	finished := make(chan [2]routeNativeReadback, 1)
	failure := errors.New("peer-native-failure")
	go func() {
		finished <- parallelRouteNativeReadbacks(context.Background(), func(context.Context) (routeFlowReply, error) { <-release; return routeFlowReply{Schema: 1}, nil }, func(context.Context) (routeFlowReply, error) { close(peerFailed); return routeFlowReply{}, failure })
	}()
	<-peerFailed
	select {
	case <-finished:
		t.Fatal("returned before original local reader completed")
	default:
	}
	close(release)
	results := <-finished
	good, bad := false, false
	for _, r := range results {
		if r.stage == "local-native" {
			good = r.err == nil && r.reply.Schema == 1
		} else {
			bad = errors.Is(r.err, failure)
		}
	}
	if !good || !bad {
		t.Fatal("owner outcomes were mixed")
	}
}
func TestRouteNativeSchedulingHintDoesNotAuthorizeMissingGate(t *testing.T) {
	gate := &routePacketGate{}
	if !gate.localRefreshFirst([32]byte{1}, nil) || gate.Allows([32]byte{1}, nil) {
		t.Fatal("absent view became native/flow permission")
	}
}
