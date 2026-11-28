// SPDX-License-Identifier: Apache-2.0

package access

import "testing"

func TestParseImageKeepsTagsAndNormalizes(t *testing.T) {
	digest := "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, c := range []struct{ in, ref, tag, digest string }{
		{"alpine", "docker.io/library/alpine:latest", "latest", ""},
		{"nginx:1.27", "docker.io/library/nginx:1.27", "1.27", ""},
		{"ghcr.io/team/web:latest", "ghcr.io/team/web:latest", "latest", ""},
		{"ghcr.io/team/web@" + digest, "ghcr.io/team/web@" + digest, "", digest},
		{"ghcr.io/team/web:v1@" + digest, "ghcr.io/team/web@" + digest, "", digest},
	} {
		i, err := ParseImage(c.in)
		if err != nil || i.Reference != c.ref || i.Tag != c.tag || i.Digest != c.digest || i.Pinned() != (c.digest != "") {
			t.Fatal(c.in, i, err)
		}
		if n, err := NormalizeImage(c.in); err != nil || n != c.ref {
			t.Fatal("normalize", c.in, n, err)
		}
	}
	for _, bad := range []string{"", digest, "Upper/Case:tag", "a b", "ghcr.io/team/web@sha512:" + digest[7:] + digest[7:]} {
		if _, err := ParseImage(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if _, err := PinImage("nginx:1.27"); err == nil {
		t.Fatal("PinImage accepted a tag")
	}
}
