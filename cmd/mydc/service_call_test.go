// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestServiceCallCLIHasNoHostSecretOrRetrySelectors(t *testing.T) {
	for _, args := range [][]string{{"shop", "api", "--port", "8080", "--path", "/decide"}, {"shop", "api", "--port", "8443", "--path", "/decide", "--scheme", "https", "--insecure-skip-verify", "--body-file", "body.json", "--header", "Content-Type=application/json", "--header", "X-MyDC-Event=check"}} {
		if _, err := parseServiceCallOptions(args, io.Discard); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"shop", "api", "--port", "8080", "--path", "http://private/"}, {"shop", "api", "--port", "8080", "--path", "/", "--host", "10.0.0.1"}, {"shop", "api", "--port", "8080", "--path", "/", "--header", "Authorization=private"}, {"shop", "api", "--port", "8080", "--path", "/", "--request-id", "retry"}, {"shop", "api", "--port", "8080", "--path", "/", "--insecure-skip-verify"}, {"shop", "api", "--port", "8080", "--path", "/", "--timeout-ms", "30001"}} {
		if _, err := parseServiceCallOptions(args, io.Discard); err == nil {
			t.Fatal("unsafe service call", args)
		}
	}
}

func TestServiceCallUserHelp(t *testing.T) {
	for _, test := range []struct{ command, fragment string }{
		{"service-call", "service-call APP SERVICE"},
	} {
		var out bytes.Buffer
		if !userHelp([]string{test.command, "--help"}, &out) || !strings.Contains(out.String(), test.fragment) {
			t.Fatal("merged user help missing", test.command)
		}
	}
}
