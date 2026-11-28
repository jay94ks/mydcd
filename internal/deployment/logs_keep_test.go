// SPDX-License-Identifier: Apache-2.0

package deployment

import "testing"

func TestAppLogKeep(t *testing.T) {
	doc := func(app, service string) []byte {
		return []byte("services:\n  web:\n    image: docker.io/library/nginx@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + "\n" + service + app)
	}
	c, err := ParseApp(doc("x-sfc: {logs: {keep: 30d}}\n", "    x-sfc: {logs: {keep: forever}}\n  api:\n    image: docker.io/library/nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateApp(); err != nil {
		t.Fatal(err)
	}
	if c.LogKeep("web") != "forever" || c.LogKeep("api") != "30d" || c.LogKeep("none") != "30d" {
		t.Fatal(c.LogKeep("web"), c.LogKeep("api"))
	}
	for _, bad := range [][]byte{doc("x-sfc: {logs: {keep: never}}\n", ""), doc("", "    x-sfc: {logs: {keep: 0d}}\n"), doc("x-sfc: {logs: {keep: 1d, limit: 5%}}\n", "")} {
		c, err := ParseApp(bad)
		if err == nil {
			err = c.ValidateApp()
		}
		if err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
