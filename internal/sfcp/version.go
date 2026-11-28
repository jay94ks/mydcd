// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// tagVersion is the optional handshake hello extension that announces the
// sender's build version, major.minor.build or major.minor.0-dev
// (buildinfo.Version, devel/design/upgrades.md 3-5, U2). A build that does
// not know the tag skips it (tag >= 128). A hello without it, or with a
// value that does not start with a major number, is not checked.
const tagVersion = 128

// maxVersion bounds the announced string.
const maxVersion = 64

// ErrMajor means the peer runs a build of another major. Majors may break
// any compatibility, so such a peer is never connected: no Raft, report or
// join path reaches it. The dialer keeps retrying with its usual backoff,
// which succeeds once one side is upgraded.
var ErrMajor = errors.New("SFCP peer runs another major")

func versionField(v string) Field { return Field{Tag: tagVersion, Value: []byte(v)} }

// helloVersion reads the announced version; a missing or malformed value is
// "" (unknown), never an error.
func helloVersion(f Frame) string {
	for _, field := range f.Fields {
		if field.Tag == tagVersion {
			v := string(field.Value)
			if len(v) == 0 || len(v) > maxVersion || strings.Trim(v, "0123456789abcdefghijklmnopqrstuvwxyz.+-") != "" {
				return ""
			}
			return v
		}
	}
	return ""
}

// versionMajor reads the leading major of a version, ok false when it has
// none.
func versionMajor(v string) (int, bool) {
	head, _, found := strings.Cut(v, ".")
	if !found || head == "" || len(head) > 4 || strings.Trim(head, "0123456789") != "" || len(head) > 1 && head[0] == '0' {
		return 0, false
	}
	n, err := strconv.Atoi(head)
	return n, err == nil
}

// checkPeerVersion refuses a peer of another major and logs a peer of the
// same major with another version once (per peer and version, per process).
func (t *Transport) checkPeerVersion(peer Peer, theirs string) error {
	if theirs == "" || theirs == t.version {
		return nil
	}
	ourMajor, ok := versionMajor(t.version)
	theirMajor, theirsOK := versionMajor(theirs)
	if !ok || !theirsOK {
		return nil
	}
	name := peer.ID
	if name == "" {
		name = fmt.Sprintf("%x", peer.Key[:6])
	}
	if t.logVersionOnce(peer.Key, theirs) {
		if theirMajor != ourMajor {
			log.Printf("SFCP peer %s runs sfcd %s (major %d); this node runs %s (major %d). Majors differ, so it is not connected", name, theirs, theirMajor, t.version, ourMajor)
		} else {
			log.Printf("SFCP peer %s runs sfcd %s; this node runs %s (same major, connected)", name, theirs, t.version)
		}
	}
	if theirMajor != ourMajor {
		return fmt.Errorf("%w: peer %s runs %s, this node %s", ErrMajor, name, theirs, t.version)
	}
	return nil
}

func (t *Transport) logVersionOnce(key Identity, version string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.versionLogged[key] == version {
		return false
	}
	if t.versionLogged == nil {
		t.versionLogged = map[Identity]string{}
	}
	t.versionLogged[key] = version
	return true
}
