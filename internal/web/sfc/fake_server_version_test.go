// SPDX-License-Identifier: Apache-2.0

package sfc

import "testing"

// readable before login; the fake's answer can be changed.
func TestServerVersion(t *testing.T) {
	f, _ := newTestFake(t)
	conn, err := f.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := conn.ServerVersion(ctx)
	if err != nil || v.Version == "" || v.Protocol != 1 || v.BuildTime == "" {
		t.Fatalf("before login %+v %v", v, err)
	}
	f.SetServerVersion(ServerVersion{Version: "0", Protocol: 0})
	alice := passwordLogin(t, f, "alice", "alice")
	if v, _ := alice.ServerVersion(ctx); v.Version != "0" || v.Protocol != 0 {
		t.Fatalf("after set %+v", v)
	}
	conn.Close()
	if _, err := conn.ServerVersion(ctx); err == nil {
		t.Fatal("closed connection answered")
	}
}
