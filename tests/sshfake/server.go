// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package sshfake is a test SSH server on loopback standing in for a node's
// sshd in the node shell tests (devel/refactor/16-fake-host-layer.md). It
// takes only the mydc-shell account's key from that account's
// authorized_keys and runs the session as that account with a real PTY, as
// sshd does. It needs root (to run as another user).
package sshfake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// Account is the only user the server lets in.
const Account = "mydc-shell"

// Server is a running test SSH server.
type Server struct {
	listener net.Listener
	config   *ssh.ServerConfig
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    map[net.Conn]bool
	closed   bool
}

// Start listens on 127.0.0.1 and writes the host's public key, in
// authorized_keys form and owned by the caller, to hostKeyFile.
func Start(hostKeyFile string) (*Server, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(hostKeyFile, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil {
		return nil, err
	}
	if err = os.Chmod(hostKeyFile, 0o644); err != nil {
		return nil, err
	}
	s := &Server{conns: map[net.Conn]bool{}}
	s.config = &ssh.ServerConfig{PublicKeyCallback: s.authorize}
	s.config.AddHostKey(signer)
	if s.listener, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Endpoint is the server's host:port.
func (s *Server) Endpoint() string { return s.listener.Addr().String() }

// Close stops the server and ends its connections.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func (s *Server) authorize(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	u, err := user.Lookup(meta.User())
	if err != nil || meta.User() != Account {
		return nil, errors.New("unknown user")
	}
	raw, err := os.ReadFile(filepath.Join(u.HomeDir, ".ssh", "authorized_keys"))
	for err == nil && len(raw) > 0 {
		var allowed ssh.PublicKey
		allowed, _, _, raw, err = ssh.ParseAuthorizedKey(raw)
		if err == nil && string(allowed.Marshal()) == string(key.Marshal()) {
			return &ssh.Permissions{}, nil
		}
	}
	return nil, errors.New("key not authorized")
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
		s.conns[c] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(c)
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	conn, channels, requests, err := ssh.NewServerConn(c, s.config)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(requests)
	u, err := user.Lookup(conn.User())
	if err != nil {
		return
	}
	for ch := range channels {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		channel, reqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go session(u, channel, reqs)
	}
}

// session runs one shell or command as u, on a PTY when one was asked for.
func session(u *user.User, channel ssh.Channel, reqs <-chan *ssh.Request) {
	defer channel.Close()
	var ptmx *os.File
	defer func() {
		if ptmx != nil {
			_ = ptmx.Close()
		}
	}()
	var size [2]uint32 // cols, rows
	term := "xterm"
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p struct {
				Term             string
				Cols, Rows, W, H uint32
				Modes            string
			}
			if ssh.Unmarshal(req.Payload, &p) != nil || ptmx != nil {
				_ = req.Reply(false, nil)
				continue
			}
			term, size = p.Term, [2]uint32{p.Cols, p.Rows}
			var err error
			if ptmx, err = openPTY(); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			resize(ptmx, size)
			_ = req.Reply(true, nil)
		case "window-change":
			if len(req.Payload) >= 8 && ptmx != nil {
				resize(ptmx, [2]uint32{binary.BigEndian.Uint32(req.Payload), binary.BigEndian.Uint32(req.Payload[4:])})
			}
			_ = req.Reply(false, nil)
		case "shell", "exec":
			args := []string{"/bin/sh"}
			if req.Type == "exec" {
				var e struct{ Command string }
				if ssh.Unmarshal(req.Payload, &e) != nil {
					_ = req.Reply(false, nil)
					continue
				}
				args = append(args, "-c", e.Command)
			}
			cmd, output, err := command(u, term, args, channel, ptmx)
			if err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			go func() {
				for r := range reqs {
					if r.Type == "window-change" && len(r.Payload) >= 8 && ptmx != nil {
						resize(ptmx, [2]uint32{binary.BigEndian.Uint32(r.Payload), binary.BigEndian.Uint32(r.Payload[4:])})
					}
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
				}
			}()
			code := 0
			if err := cmd.Wait(); err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					code = 255
				} else if code = exit.ExitCode(); code < 0 {
					code = 255
				}
			}
			// The rest of the screen, until the PTY reports the child's
			// side closed.
			<-output
			_, _ = channel.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, uint32(code)))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// command starts args as u; output closes when its output has all been
// sent.
func command(u *user.User, term string, args []string, channel ssh.Channel, ptmx *os.File) (*exec.Cmd, chan struct{}, error) {
	output := make(chan struct{})
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = u.HomeDir
	cmd.Env = []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "SHELL=/bin/sh", "PATH=/usr/local/bin:/usr/bin:/bin", "TERM=" + term, "PS1=$ "}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, Setsid: true}
	if ptmx == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = channel, channel, channel.Stderr()
		close(output)
		return cmd, output, cmd.Start()
	}
	tty, err := openTTY(ptmx)
	if err != nil {
		return nil, nil, err
	}
	defer tty.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr.Setctty = true
	if err = cmd.Start(); err != nil {
		return nil, nil, err
	}
	go func() { _, _ = io.Copy(ptmx, channel) }()
	go func() { _, _ = io.Copy(channel, ptmx); close(output) }()
	return cmd, output, nil
}

func openPTY() (*os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/dev/ptmx"), nil
}

func openTTY(ptmx *os.File) (*os.File, error) {
	n, err := unix.IoctlGetUint32(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
}

func resize(ptmx *os.File, size [2]uint32) {
	_ = unix.IoctlSetWinsize(int(ptmx.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(size[0]), Row: uint16(size[1])})
}
