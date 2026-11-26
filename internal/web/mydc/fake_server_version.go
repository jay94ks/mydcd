// SPDX-License-Identifier: Apache-2.0

package mydc

import "context"

// FixtureServerVersion is what the fake answers until SetServerVersion.
var FixtureServerVersion = ServerVersion{Version: "1", Protocol: 1, Commit: "f1fe471", BuildTime: "2026-11-15T08:00:00Z"}

// SetServerVersion changes the server-version answer (e.g. an older
// Protocol to test the web's mismatch notice).
func (f *Fake) SetServerVersion(v ServerVersion) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = &v
}

func (c *fakeConn) ServerVersion(ctx context.Context) (ServerVersion, error) {
	const m = "server-version"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, false); err != nil {
		return ServerVersion{}, err
	}
	if c.f.version != nil {
		return *c.f.version, nil
	}
	return FixtureServerVersion, nil
}
