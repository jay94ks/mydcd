// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

// A browser that drops a read does not cancel the sfcd call (it would close
// the login's shared connection); a dropped write still does.
func TestCallCtxDetachesReadsFromRequestCancel(t *testing.T) {
	s := &Server{opt: Options{CallTimeout: time.Minute}}
	for _, c := range []struct {
		method   string
		detached bool
	}{{"GET", true}, {"HEAD", true}, {"POST", false}, {"PUT", false}, {"DELETE", false}} {
		parent, cancel := context.WithCancel(context.Background())
		r := httptest.NewRequest(c.method, "/api/v1/raft", nil).WithContext(parent)
		ctx, done := s.callCtx(r)
		cancel()
		if got := ctx.Err() == nil; got != c.detached {
			t.Errorf("%s: detached=%v", c.method, got)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Errorf("%s: no CallTimeout", c.method)
		}
		done()
	}
}
