// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"crypto/sha256"
	"testing"
)

func TestSendLossAndReplyOrders(t *testing.T) {
	digest := sha256.Sum256([]byte("command"))
	for _, event := range []string{"disconnect", "timeout", "cancel"} {
		t.Run(event, func(t *testing.T) {
			r, _ := NewRequest("id", digest)
			before := r.Abandon()
			if before.Phase() != NotSent || !before.SafeToRetry() {
				t.Fatal("pre-send loss is not classified as unsent")
			}
			if _, err := before.BeginSend(); err == nil {
				t.Fatal("terminal request automatically resent")
			}
			sent, err := r.BeginSend()
			if err != nil {
				t.Fatal(err)
			}
			lost := sent.Abandon()
			if lost.Phase() != Unknown || lost.SafeToRetry() {
				t.Fatal("post-send loss allowed blind retry")
			}
			if _, err := lost.Reply("id", digest); err == nil {
				t.Fatal("late response changed terminal uncertainty")
			}
			if _, err := lost.BeginSend(); err == nil {
				t.Fatal("unknown request automatically resent")
			}
			completed, err := sent.Reply("id", digest)
			if err != nil || completed.Phase() != Completed || completed.Abandon() != completed || completed.SafeToRetry() {
				t.Fatal("completed request lost its result")
			}
		})
	}
}

func TestRequestBindingAndInvalidTransitions(t *testing.T) {
	digest := sha256.Sum256([]byte("command"))
	if _, err := NewRequest("", digest); err == nil {
		t.Fatal("empty identity accepted")
	}
	r, _ := NewRequest("id", digest)
	if _, err := r.Reply("id", digest); err == nil {
		t.Fatal("reply accepted before send")
	}
	r, _ = r.BeginSend()
	if _, err := r.BeginSend(); err == nil {
		t.Fatal("sent request sent again")
	}
	for _, reply := range []struct {
		id     string
		digest [32]byte
	}{{"other", digest}, {"id", sha256.Sum256([]byte("other command"))}} {
		n, err := r.Reply(reply.id, reply.digest)
		if err == nil || n != r {
			t.Fatal("unrelated response changed request")
		}
	}
}
