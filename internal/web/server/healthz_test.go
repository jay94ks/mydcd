// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"testing"
)

// ingress checks the web cluster app without a session
func TestHealthzNeedsNoSession(t *testing.T) {
	f := newFixture(t)
	res, err := f.hc.Get(f.http.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "ok\n" {
		t.Fatalf("healthz: %d %q", res.StatusCode, body)
	}
}
