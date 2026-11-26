// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"testing"
)

func TestCDFileDefaultsAndRoundTrip(t *testing.T) {
	p, err := ParseCDFile([]byte("version: 1\nrepository: https://git.example.com/shop.git\nbranch: main\npath: deploy/app.yaml\nsync: auto\nprune: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || p.Poll != 60 || p.Sync.Mode != "automatic" || p.Sync.Drift != "report" || !p.Sync.Prune || p.Source.Kind != "git" || p.Limits.Fetch != 30 || p.Limits.Bytes != 4<<20 {
		t.Fatalf("defaults: %+v", p)
	}
	f := CDFileOf(p)
	if f.Sync != "auto" || f.Poll != "1m0s" || f.Drift != "report" {
		t.Fatalf("file form: %+v", f)
	}
	back, err := f.Declaration()
	if err != nil || back.Sync != p.Sync || back.Source != p.Source || back.Poll != p.Poll {
		t.Fatal("round trip changed the policy", back, err)
	}
	for _, bad := range []string{
		"version: 2\nrepository: r\nbranch: b\npath: p\n",
		"version: 1\nbranch: b\npath: p\n",
		"version: 1\nrepository: r\nbranch: b\npath: p\npoll: 500ms\n",
		"version: 1\nrepository: r\nbranch: b\npath: p\nsync: sometimes\n",
		"version: 1\nrepository: r\nbranch: b\npath: p\ndrift: ignore\n",
		"version: 1\nrepository: r\nbranch: b\npath: p\nunknown: 1\n",
	} {
		if _, err := ParseCDFile([]byte(bad)); !errors.Is(err, ErrCDFile) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
