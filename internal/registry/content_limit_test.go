// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/registryclient"
)

// This proves only HTTP size admission/configuration, without allocating or
// claiming persistence of a 10GiB body. Actual upload/store/SDK checks remain
// separate RQ6 adapter evidence and must not inherit this test's scope.
func TestRegistryHTTPBodyAdmissionCanRepresentTenGiBPushWithoutAllocation(t *testing.T) {
	spec, _, _ := serverFixture(t)
	spec.Blobs.BlobBytes = registryclient.MaxImageBytes
	spec.Blobs.TotalBytes = 2 * registryclient.MaxImageBytes
	spec.RequestTimeoutMS = 300000
	if err := spec.Validate([32]byte{1}); err != nil {
		t.Fatal("10GiB configured capacity refused", err)
	}
	calls := 0
	s := &Server{spec: spec, active: make(chan struct{}, spec.MaxRequests), server: &http.Server{ErrorLog: log.New(io.Discard, "", 0)}, auth: Authorization{Check: func(context.Context, string, Permission) error { return nil }}, content: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.ContentLength != registryclient.MaxImageBytes {
			t.Error("wrong accepted body limit")
		}
		w.WriteHeader(204)
	})}
	for _, tc := range []struct {
		length int64
		status int
	}{{registryclient.MaxImageBytes, 204}, {registryclient.MaxImageBytes + 1, 413}} {
		request := httptest.NewRequest("PATCH", "https://"+spec.Authority+"/v2/team/app/blobs/uploads/00112233445566778899aabbccddeeff", strings.NewReader(""))
		request.ContentLength = tc.length
		request.Host = spec.Authority
		request.Header.Set("Authorization", "Bearer private-test")
		response := httptest.NewRecorder()
		s.handle(response, request)
		if response.Code != tc.status {
			t.Fatal(tc, response.Code)
		}
	}
	if calls != 1 {
		t.Fatal("oversized body reached storage", calls)
	}
}
