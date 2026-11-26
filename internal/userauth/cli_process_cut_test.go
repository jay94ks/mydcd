// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/wallet"
)

type e7CLIReplyGate struct {
	reached, release chan struct{}
	once             sync.Once
	releaseOnce      sync.Once
}

func (g *e7CLIReplyGate) unblock() { g.releaseOnce.Do(func() { close(g.release) }) }

type e7CLIProcess struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
}
type e7CLIBlockedReply struct {
	mydcp.Stream
	gate *e7CLIReplyGate
	ctx  context.Context
}

func (s *e7CLIBlockedReply) Write(raw []byte) (int, error) {
	s.gate.once.Do(func() { close(s.gate.reached) })
	select {
	case <-s.gate.release:
		return s.Stream.Write(raw)
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	}
}

// The prebuilt real CLI is killed AFTER the real service commits but BEFORE
// its response enters the actual MYDCP stream. No product hook or fake result.
func TestE7ActualCLIInterruptAndKillPreserveOriginalWireOperation(t *testing.T) {
	binary := os.Getenv("MYDC_TEST_CLI")
	if !filepath.IsAbs(binary) {
		t.Skip("requires ordinary-user prebuilt final mydc")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, home := t.TempDir(), t.TempDir()
	node, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(node.Private)
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	clusterID := [32]byte{177}
	peer := mydcp.Peer{ID: "node", Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Member: true, Read: true, Respond: true}}
	lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
		if key == mydcp.Identity(self.Public) {
			return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
		}
		return peer, key == peer.Key
	}
	server, err := mydcp.NewTransport(node, clusterID, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer.Endpoint = "unix://" + filepath.Join(root, "management.sock")
	clientMesh, err := mydcp.NewTransport(self, clusterID, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer clientMesh.Close()
	policy := control.Policy{Cluster: clusterID, BootstrapKey: self.Public, Issuers: [][32]byte{node.Public}}
	e, err := cluster.Open(cluster.Options{ID: "node", Root: filepath.Join(root, "state"), Admin: self.Actor(), Cluster: clusterID, Mesh: server, Bootstrap: true, Servers: []raft.Server{{ID: "node", Address: raft.ServerAddress(server.Addr().String()), Suffrage: raft.Voter}}, Resolve: func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) { return peer, id == "node" }, ModuleID: policy.ID(), Validate: policy.Validate, Reduce: policy.Reduce, AdmitModule: policy.AdmitModule})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for {
		if _, err := e.Read(ctx, true); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	raw, err := control.ChangeBytes("enroll", "", 0, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := e.Submit(ctx, state.Command{Kind: state.Module, Actor: self.Actor(), Epoch: 1, RequestID: "enroll", Key: control.CatalogKey, Value: string(raw)})
	if err != nil || enrolled.Result.Code != state.Applied {
		t.Fatal("actual enrollment", enrolled, err)
	}
	gates := map[string]*e7CLIReplyGate{}
	for _, id := range []string{"cli-int", "cli-kill"} {
		gates[id] = &e7CLIReplyGate{reached: make(chan struct{}), release: make(chan struct{})}
	}
	defer func() {
		for _, gate := range gates {
			gate.unblock()
		}
	}()
	var children []*e7CLIProcess
	defer func() {
		for _, child := range children {
			_ = child.command.Process.Kill()
			<-child.done
		}
	}()
	svc := Service{Engine: e, Mesh: server, Self: node, Policy: policy}
	if err := server.OnManagement(mydcp.User, func(call context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
		var envelope Envelope
		var request Request
		if len(frame.Fields) > 0 && json.Unmarshal(frame.Fields[0].Value, &envelope) == nil && json.Unmarshal(envelope.Body, &request) == nil && request.Method == "submit" && request.Operation != nil {
			if gate := gates[request.Operation.RequestID]; gate != nil {
				stream = &e7CLIBlockedReply{Stream: stream, gate: gate, ctx: call}
			}
		}
		return svc.handle(call, conn, stream, frame)
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(filepath.Join(root, "management.sock")); err != nil {
		t.Fatal(err)
	}
	c := Client{Mesh: clientMesh, Self: self, Cluster: clusterID, Peers: []mydcp.Peer{peer}}
	password := []byte("private-e7-cli-process-wallet")
	disk, err := wallet.OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.Init(password); err != nil {
		disk.Close()
		t.Fatal(err)
	}
	_ = disk.Close()
	credentials, err := OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	session, err := credentials.LoginPrivate(ctx, c, peer, "admin", self.Private)
	_ = credentials.Close()
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node, key: '%x', endpoint: '%s', voter: true}\n", clusterID, node.Public, peer.Endpoint)), 0600); err != nil {
		t.Fatal(err)
	}
	startCLI := func(args []string) (*e7CLIProcess, *bytes.Buffer, *bytes.Buffer) {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(password); err != nil {
			r.Close()
			w.Close()
			t.Fatal(err)
		}
		_ = w.Close()
		command := exec.CommandContext(ctx, binary, append([]string{"--config", profile, "--user", "admin", "--wallet-password-fd", "3", "--no-input"}, args...)...)
		command.ExtraFiles = []*os.File{r}
		command.Env = append([]string{"HOME=" + home, "GOMAXPROCS=2"}, "PATH="+os.Getenv("PATH"))
		var out, diagnostic bytes.Buffer
		command.Stdout = &out
		command.Stderr = &diagnostic
		err = command.Start()
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
		process := &e7CLIProcess{command: command, done: make(chan struct{})}
		children = append(children, process)
		go func() { process.err = command.Wait(); close(process.done) }()
		return process, &out, &diagnostic
	}
	for i, id := range []string{"cli-int", "cli-kill"} {
		gate := gates[id]
		change := filepath.Join(root, id+".json")
		raw, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: "create-tenant", Payload: json.RawMessage(fmt.Sprintf(`{"ID":%q}`, id))})
		if err := os.WriteFile(change, raw, 0600); err != nil {
			t.Fatal(err)
		}
		child, _, diagnostic := startCLI([]string{"manage", "apply", "--request-id", id, "--change", change})
		select {
		case <-gate.reached:
		case <-child.done:
			t.Fatalf("CLI ended before actual committed response: %v %s", child.err, diagnostic.String())
		case <-ctx.Done():
			_ = child.command.Process.Kill()
			<-child.done
			t.Fatal(ctx.Err())
		}
		original, err := LoadOperation(home, c, session, id)
		if err != nil {
			_ = child.command.Process.Kill()
			gate.unblock()
			<-child.done
			t.Fatal(err)
		}
		command, err := original.Operation.Command()
		if err != nil {
			t.Fatal(err)
		}
		view, err := e.Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		receipt, found := view.State.LookupResult(command)
		if !found || receipt.Code != state.Applied {
			t.Fatal("gate did not follow actual commit")
		}
		signal := syscall.SIGINT
		if i == 1 {
			signal = syscall.SIGKILL
		}
		if err := child.command.Process.Signal(signal); err != nil {
			t.Fatal(err)
		}
		select {
		case <-child.done:
			if child.err == nil {
				t.Fatal("interrupted actual CLI reported success")
			}
		case <-ctx.Done():
			_ = child.command.Process.Kill()
			<-child.done
			t.Fatal(ctx.Err())
		}
		gate.unblock()
		if original.Result != nil {
			t.Fatal("reply gate allowed a result before interruption")
		}
		process, out, diagnostic := startCLI([]string{"manage", "resume", "--request-id", id})
		<-process.done
		if err := process.err; err != nil {
			t.Fatalf("original explicit resume: %v %s", err, diagnostic.String())
		}
		var settled struct {
			Result state.Result `json:"result"`
		}
		if json.Unmarshal(out.Bytes(), &settled) != nil || settled.Result != receipt {
			t.Fatal("CLI did not return exact original receipt")
		}
		after, err := LoadOperation(home, c, session, id)
		if err != nil || after.Result == nil || *after.Result != receipt || !bytes.Equal(control.OperationBytes(after.Operation), control.OperationBytes(original.Operation)) || !bytes.Equal(after.Operation.Signature, original.Operation.Signature) {
			t.Fatal("CLI changed original signed operation", err)
		}
	}
	if err := e.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("actual CLI SIGINT/SIGKILL after real Raft/bbolt commit before MYDCP response; encrypted-wallet private intent preserved; explicit resume exact original receipt/signature with no new mutation")
}
