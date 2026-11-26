// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestLowerCamel(t *testing.T) {
	for in, want := range map[string]string{
		"ID": "id", "CPUPercent": "cpuPercent", "NodeA": "nodeA", "CIDR": "cidr", "URLs": "urls",
		"RTTMillis": "rttMillis", "App": "app", "PIDs": "pids", "MemRSS": "memRSS",
	} {
		if got := lowerCamel(in); got != want {
			t.Errorf("lowerCamel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCamelJSON(t *testing.T) {
	type inner struct{ NodeID string }
	type v struct {
		inner
		Name    string
		Key     [4]byte
		Data    []byte
		Values  map[string]int
		Skip    string `json:"-"`
		Opt     string `json:",omitempty"`
		Renamed string `json:"custom"`
		List    []string
		At      time.Time
	}
	got, err := camelJSON(v{inner: inner{"n1"}, Name: "a", Key: [4]byte{1, 2, 3, 4}, Data: []byte("hi"), Values: map[string]int{"DB_PASSWORD": 1}, Renamed: "r", At: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"nodeID":"n1","name":"a","key":"01020304","data":"aGk=","values":{"DB_PASSWORD":1},"custom":"r","list":[],"at":"1970-01-01T00:00:00Z"}`
	if string(got) != want {
		t.Fatalf("camelJSON:\n got %s\nwant %s", got, want)
	}
}
