// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
)

type fakeShell struct {
	commands []string
	stdin    []string
	out      map[string]string
	fail     string
}

func (f *fakeShell) Run(_ context.Context, command string, stdin io.Reader) ([]byte, error) {
	f.commands = append(f.commands, command)
	in := ""
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		in = string(b)
	}
	f.stdin = append(f.stdin, in)
	if f.fail != "" && strings.Contains(command, f.fail) {
		return nil, errors.New("exit 1")
	}
	for k, v := range f.out {
		if strings.Contains(command, k) {
			return []byte(v), nil
		}
	}
	return nil, nil
}
func (f *fakeShell) Close() error { return nil }

func TestVPSSSHInstallAndJoin(t *testing.T) {
	key := strings.Repeat("ab", 32)
	build := control.VPSBuild{OS: "linux", Arch: "amd64", SHA256: [32]byte{0xaa}}
	sh := &fakeShell{out: map[string]string{"identity": key + "\n"}}
	got, err := vpsSSHInstall(context.Background(), sh, strings.NewReader("BINARY"), build)
	if err != nil || got != key || sh.stdin[0] != "BINARY" || !strings.Contains(sh.commands[0], "aa00000000") || !strings.Contains(sh.commands[0], "sha256sum -c") {
		t.Fatalf("install = %q %v %q", got, err, sh.commands)
	}
	if !strings.Contains(sh.commands[1], "identity show") || !strings.Contains(sh.commands[1], "identity create") {
		t.Fatal("identity must be reused on retry", sh.commands[1])
	}
	if _, err := vpsSSHInstall(context.Background(), &fakeShell{out: map[string]string{"identity": "garbage"}}, strings.NewReader(""), build); err == nil {
		t.Fatal("bad identity output accepted")
	}
	if _, err := vpsSSHInstall(context.Background(), &fakeShell{fail: "sha256sum"}, strings.NewReader(""), build); err == nil {
		t.Fatal("checksum failure ignored")
	}

	server := control.VPSServer{Name: "edge-1", Phase: control.VPSInstalling, PublicIP: "203.0.113.9", Port: 7443}
	sourceKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	sourceHex := hex.EncodeToString(sourceKey.Public().(ed25519.PublicKey))
	genesis := config.Peer{ID: "node-a", Key: sourceHex, Endpoint: "192.0.2.1:7443", Voter: true}
	inv := &membership.Invitation{Schema: 1, Cluster: [32]byte{1}, Admin: [32]byte{2}, Genesis: genesis, Source: genesis, Target: config.Peer{ID: "edge-1", Key: key, Endpoint: "203.0.113.9:7443"},
		JoinID: "vps-x", ApprovalRevision: 2, MinimumIndex: 1}
	inv.Signature = ed25519.Sign(sourceKey, membership.InvitationBytes(*inv))
	sh = &fakeShell{}
	if err := vpsSSHJoin(context.Background(), sh, server, inv); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(sh.stdin, "\n")
	if !strings.Contains(all, "inbound_only: true") || !strings.Contains(all, `listen: "203.0.113.9:7443"`) || !strings.Contains(all, "ExecStart=/usr/local/bin/sfcd") {
		t.Fatal("files", all)
	}
	last := sh.commands[len(sh.commands)-1]
	if !strings.Contains(last, "join --cluster 0100") || !strings.Contains(last, "--source-public-key "+sourceHex) || !strings.Contains(last, "systemctl enable --now sfcd") {
		t.Fatal("join", last)
	}
}

func TestVPSSSHPending(t *testing.T) {
	s := control.VPSServer{Phase: control.VPSInstalling}
	if !vpsSSHPending(s, membership.Entry{}, false) {
		t.Fatal("not enrolled yet")
	}
	if vpsSSHPending(s, membership.Entry{Phase: membership.Invited}, true) {
		t.Fatal("waits for the invitation")
	}
	s.Invitation = &membership.Invitation{}
	if !vpsSSHPending(s, membership.Entry{Phase: membership.Invited}, true) || vpsSSHPending(s, membership.Entry{Phase: membership.Learner}, true) {
		t.Fatal("join once invited, stop once joined")
	}
	s.Script = "S1"
	if vpsSSHPending(s, membership.Entry{}, false) {
		t.Fatal("a scripted server enrolls itself")
	}
}

func TestVPSHostKeyPinnedAfterFirstContact(t *testing.T) {
	a, _ := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, 32)).Public())
	b, _ := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public())
	var seen []byte
	if err := vpsHostKeyCheck(nil, &seen)("", nil, a); err != nil || !bytes.Equal(seen, a.Marshal()) {
		t.Fatal("first contact", err)
	}
	if err := vpsHostKeyCheck(seen, new([]byte))("", nil, a); err != nil {
		t.Fatal("same key refused", err)
	}
	if err := vpsHostKeyCheck(seen, new([]byte))("", nil, b); !errors.Is(err, errVPSHostKey) {
		t.Fatal("changed key accepted", err)
	}
}
