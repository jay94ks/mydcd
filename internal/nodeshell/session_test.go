// SPDX-License-Identifier: Apache-2.0

package nodeshell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The SSH server is test-only: it validates actual client transport, host pins,
// PTY/resize/EOF/exit frames, not an installed sshd or an actual OS account.
func nodeShellSSHFixture(t *testing.T) (*Adapter, <-chan string, <-chan [2]uint32) {
	t.Helper()
	a := adapterFixture(t)
	record := accountRecord{Schema: 1, Account: Account, Home: a.config.Home, UID: "10001", GID: "10002"}
	raw, _ := json.Marshal(record)
	if err := createOrMatch(filepath.Join(a.config.StateDir, "account.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	a.lookup = func(string) (*user.User, error) {
		return &user.User{Username: Account, Name: "Seafield Cluster node shell", HomeDir: record.Home, Uid: record.UID, Gid: record.GID}, nil
	}
	clientKey, err := a.signer(true)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.config.HostPublicKeyFile, ssh.MarshalAuthorizedKey(host.PublicKey()), 0644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a.config.Endpoint, a.ready = listener.Addr().String(), PublicReady{Ready: true, Account: Account}
	commands := make(chan string, 4)
	sizes := make(chan [2]uint32, 4)
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != Account || !bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
			return nil, ErrNotReady
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(host)
	connections := make(chan net.Conn, 4)
	t.Cleanup(func() {
		_ = listener.Close()
		for {
			select {
			case conn := <-connections:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections <- conn
			go func() {
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for opened := range channels {
					if opened.ChannelType() != "session" {
						_ = opened.Reject(ssh.Prohibited, "session only")
						continue
					}
					channel, requests, err := opened.Accept()
					if err != nil {
						return
					}
					go func() {
						defer channel.Close()
						for request := range requests {
							switch request.Type {
							case "pty-req":
								var pty struct {
									Term             string
									Cols, Rows, X, Y uint32
									Modes            string
								}
								if ssh.Unmarshal(request.Payload, &pty) != nil {
									_ = request.Reply(false, nil)
									continue
								}
								sizes <- [2]uint32{pty.Cols, pty.Rows}
								_ = request.Reply(true, nil)
							case "window-change":
								if len(request.Payload) == 16 {
									sizes <- [2]uint32{binary.BigEndian.Uint32(request.Payload), binary.BigEndian.Uint32(request.Payload[4:])}
								}
								_ = request.Reply(true, nil)
							case "exec":
								var command struct{ Command string }
								if ssh.Unmarshal(request.Payload, &command) != nil {
									_ = request.Reply(false, nil)
									continue
								}
								commands <- command.Command
								_ = request.Reply(true, nil)
								go func() {
									_, _ = io.Copy(channel, channel)
									_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
									_ = channel.Close()
								}()
							default:
								_ = request.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	return a, commands, sizes
}

func TestNodeShellSSHUsesExactHostPinPTYAttributionAndOriginalExit(t *testing.T) {
	a, commands, sizes := nodeShellSSHFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	username := "alice'; printf injected; '"
	session, err := a.Open(ctx, 80, 24, username)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := <-commands; got != "export SFC_USER='alice'\"'\"'; printf injected; '\"'\"''; exec /bin/sh -l" {
		t.Fatal("attribution was not literal quoted data", got)
	}
	if got := <-sizes; got != [2]uint32{80, 24} {
		t.Fatal("initial PTY dimensions", got)
	}
	if err := session.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	if got := <-sizes; got != [2]uint32{120, 40} {
		t.Fatal("resize dimensions", got)
	}
	if _, err := session.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(session, got); err != nil || string(got) != "hello" {
		t.Fatal("PTY stream did not preserve bytes", string(got), err)
	}
	if err := session.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(session); err != nil {
		t.Fatal("output EOF", err)
	}
	exit, err := session.Wait()
	if err != nil || exit.Code != 0 || exit.Signal != "" {
		t.Fatal("original SSH exit status", exit, err)
	}
}

func TestNodeShellSSHRejectsWrongHostAndCancellationClosesOriginalChannel(t *testing.T) {
	a, _, _ := nodeShellSSHFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)))
	if err := os.WriteFile(a.config.HostPublicKeyFile, ssh.MarshalAuthorizedKey(key.PublicKey()), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Open(ctx, 80, 24, "alice"); err == nil {
		t.Fatal("substituted sshd host key was accepted")
	}
	b, _, _ := nodeShellSSHFixture(t)
	live, stop := context.WithCancel(ctx)
	session, err := b.Open(live, 80, 24, "alice")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	// EOF terminates the output stream, but completion still requires the
	// original SSH Wait below rather than assuming process exit from EOF.
	if _, err := io.ReadAll(session); err != nil {
		t.Fatal("cancellation output EOF", err)
	}
	done := make(chan struct{})
	go func() { _, _ = session.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("cancellation left the original SSH session waiting")
	}
	_ = session.Close()
}

func TestNodeShellSSHCloseUnblocksReadWithEOFAndRetainsActualWait(t *testing.T) {
	for _, end := range []string{"close", "cancel"} {
		t.Run(end, func(t *testing.T) {
			a, commands, _ := nodeShellSSHFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			live, stop := context.WithCancel(ctx)
			defer stop()
			session, err := a.Open(live, 80, 24, "alice")
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			<-commands // The actual SSH exec was accepted; the peer is silent.
			type readResult struct {
				n   int
				err error
			}
			reading := make(chan struct{})
			read := make(chan readResult, 1)
			go func() {
				close(reading)
				n, err := session.Read(make([]byte, 1))
				read <- readResult{n, err}
			}()
			<-reading
			select {
			case result := <-read:
				t.Fatal("silent SSH output ended before local close", result)
			default:
			}
			closed := make(chan struct{})
			go func() {
				if end == "cancel" {
					stop()
				} else {
					_ = session.Close()
				}
				close(closed)
			}()
			select {
			case <-closed:
			case <-ctx.Done():
				t.Fatal("local close waited for a stream consumer or SSH Wait")
			}
			select {
			case result := <-read:
				if result.n != 0 || result.err != io.EOF {
					t.Fatal("local close did not expose terminal EOF", result)
				}
			case <-ctx.Done():
				t.Fatal("local close left the output read blocked")
			}
			type waitResult struct {
				exit Exit
				err  error
			}
			waited := make(chan waitResult, 1)
			go func() {
				exit, err := session.Wait()
				waited <- waitResult{exit, err}
			}()
			select {
			case result := <-waited:
				// The connection was closed without an SSH exit-status frame.
				// EOF alone must not fabricate a successful native exit.
				if result.err == nil || result.exit.Code != 255 {
					t.Fatal("forced SSH close lost the actual Wait failure", result)
				}
			case <-ctx.Done():
				t.Fatal("local close did not finish the original SSH Wait")
			}
		})
	}
}

func TestNodeShellSSHClosePreservesExistingOutputError(t *testing.T) {
	a, _, _ := nodeShellSSHFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := a.Open(ctx, 80, 24, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	want := errors.New("original output failure")
	if err := session.writer.CloseWithError(want); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := session.Read(make([]byte, 1)); n != 0 || err != want {
		t.Fatal("local close masked the original output failure", n, err)
	}
}
