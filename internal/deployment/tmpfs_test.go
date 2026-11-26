// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"strings"
	"testing"
)

func TestComposeTmpfsExactOptionsAndResolvedBudget(t *testing.T) {
	s := ComposeService{Tmpfs: []string{"/scratch:size=4m,mode=0700,uid=10001,gid=10002"}}
	mounts, err := s.TmpfsMounts(32 << 20)
	if err != nil || len(mounts) != 1 || mounts[0].SizeBytes != 4<<20 || mounts[0].Mode != 0700 || mounts[0].UID != 10001 || mounts[0].GID != 10002 {
		t.Fatal("typed tmpfs conversion", mounts, err)
	}
	parsed, err := ParseCompose([]byte("name: tmpfs-app\nservices:\n  web:\n    image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n    mem_limit: 32m\n    tmpfs: [\"/scratch:size=4m,mode=0700,uid=10001,gid=10002\"]\n"))
	if err != nil {
		t.Fatal("Compose library tmpfs conversion", err)
	}
	converted, err := parsed.Services["web"].TmpfsMounts(32 << 20)
	if err != nil || len(converted) != 1 || converted[0] != mounts[0] {
		t.Fatal("Compose library dropped bounded tmpfs options", converted, err)
	}
	for _, raw := range []string{"/scratch", "/scratch:mode=0700", "/scratch:size=0", "/scratch:size=1m,size=2m", "/scratch:size=1m,exec=true", "/scratch:size=1m,mode=10000", "/scratch:size=1m,uid=4294967296", "/proc/data:size=1m", "/scratch:size=9223372036854775808"} {
		s.Tmpfs = []string{raw}
		if _, err := s.TmpfsMounts(32 << 20); err == nil {
			t.Fatal("unbounded/ambiguous tmpfs", raw)
		}
	}
	s.Tmpfs = []string{"/run:size=4m"}
	s.Secrets = SecretMounts{{Target: "/run/secrets/password"}}
	if _, err = s.TmpfsMounts(32 << 20); err == nil {
		t.Fatal("tmpfs hid a private secret mount")
	}
	f := makeFixture(t)
	input := smallCompose(t)
	web := input.Services["web"]
	web.Memory = ""
	web.Tmpfs = []string{"/scratch:size=32m"}
	input.Services["web"] = web
	ctx := contextFor(t, f)
	node := ctx.Nodes["node-a"]
	node.DefaultMemory = 16 << 20
	ctx.Nodes["node-a"] = node
	if _, err = Compile(input, f.c, ctx); err == nil || !strings.Contains(err.Error(), "INVALID_TMPFS") {
		t.Fatal("node-default budget was not applied", err)
	}
}
