// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/schema"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

const MaxProbeFrameBytes = 2 << 20
const MaxProbeCalls = 256

var ErrProbeRPC = errors.New("checker probe channel failed")

// ProbeCall is private script IPC, never a node RPC or a container-state fact.
// Its identity binds one call to the original check; native adapters still
// enforce current Task/tenant permission before an external effect.
type ProbeCall struct {
	Schema            uint8
	Binding           [32]byte
	Sequence          uint64
	DeadlineUnixMilli int64
	Kind              string
	HTTP              *contract.HTTPProbe       `json:",omitempty"`
	TCP               *contract.TCPProbe        `json:",omitempty"`
	Exec              *contract.ExecProbe       `json:",omitempty"`
	File              *contract.FileProbe       `json:",omitempty"`
	Dependency        *contract.DependencyProbe `json:",omitempty"`
}

func (c ProbeCall) ID() [32]byte {
	raw, _ := json.Marshal(struct {
		Binding  [32]byte
		Sequence uint64
	}{c.Binding, c.Sequence})
	return sha256.Sum256(append([]byte("sfc-checker-probe-call-1\x00"), raw...))
}

func (c ProbeCall) Digest() [32]byte { raw, _ := json.Marshal(c); return sha256.Sum256(raw) }

// TargetService binds a typed payload to the same selected target as its
// outer native authorization header. It is not a permission check.
func (c ProbeCall) TargetService(request contract.Request) (string, error) {
	if ValidateRequest(request) != nil || !c.valid(request, c.Sequence) || c.Kind == "hello" {
		return "", ErrContract
	}
	service := ""
	switch c.Kind {
	case "healthz":
		service = c.HTTP.Service
	case "connect":
		service = c.TCP.Service
	case "exec":
		service = c.Exec.Service
	case "file":
		service = c.File.Service
	case "dependency":
		service = c.Dependency.Service
	default:
		return "", ErrContract
	}
	if service == "" && len(request.Targets) == 1 {
		service = request.Targets[0].Service
	}
	for _, target := range request.Targets {
		if target.Service == service {
			return service, nil
		}
	}
	return "", ErrReference
}

type ProbeReply struct {
	Schema     uint8
	Binding    [32]byte
	Sequence   uint64
	Kind       string
	Failed     bool
	HTTP       *contract.HTTPResult       `json:",omitempty"`
	TCP        *contract.TCPResult        `json:",omitempty"`
	Exec       *contract.ExecResult       `json:",omitempty"`
	File       *contract.FileResult       `json:",omitempty"`
	Dependency *contract.DependencyResult `json:",omitempty"`
}

type ProbeDispatch func(context.Context, ProbeCall) (ProbeReply, error)

func (c ProbeCall) valid(request contract.Request, sequence uint64) bool {
	if c.Schema != 1 || c.Binding != requestDigest(request) || c.Sequence != sequence || c.DeadlineUnixMilli <= 0 || c.DeadlineUnixMilli > request.DeadlineUnixMilli {
		return false
	}
	count := 0
	for _, present := range []bool{c.HTTP != nil, c.TCP != nil, c.Exec != nil, c.File != nil, c.Dependency != nil} {
		if present {
			count++
		}
	}
	if c.Kind == "hello" {
		return sequence == 0 && count == 0 && c.DeadlineUnixMilli == request.DeadlineUnixMilli
	}
	return sequence > 0 && sequence <= MaxProbeCalls && count == 1 && (c.Kind == "healthz" && c.HTTP != nil || c.Kind == "connect" && c.TCP != nil || c.Kind == "exec" && c.Exec != nil || c.Kind == "file" && c.File != nil || c.Kind == "dependency" && c.Dependency != nil)
}

func (r ProbeReply) valid(call ProbeCall) bool {
	if r.Schema != 1 || r.Binding != call.Binding || r.Sequence != call.Sequence || r.Kind != call.Kind {
		return false
	}
	count := 0
	for _, present := range []bool{r.HTTP != nil, r.TCP != nil, r.Exec != nil, r.File != nil, r.Dependency != nil} {
		if present {
			count++
		}
	}
	if r.Failed || call.Kind == "hello" {
		return count == 0
	}
	return count == 1 && (call.Kind == "healthz" && r.HTTP != nil || call.Kind == "connect" && r.TCP != nil || call.Kind == "exec" && r.Exec != nil || call.Kind == "file" && r.File != nil || call.Kind == "dependency" && r.Dependency != nil)
}

// Validate applies the same binding/shape check as the compiled Probe IPC.
// A native adapter must still validate current authority and typed values.
func (r ProbeReply) Validate(call ProbeCall) error {
	if !r.valid(call) {
		return ErrProbeRPC
	}
	return nil
}

func writeProbeFrame(w io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > MaxProbeFrameBytes {
		return ErrProbeRPC
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	if err := writeProbeBytes(w, size[:]); err != nil {
		return err
	}
	return writeProbeBytes(w, raw)
}

func writeProbeBytes(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) || n == 0 && err == nil {
			return ErrProbeRPC
		}
		p = p[n:]
		if err != nil {
			return ErrProbeRPC
		}
	}
	return nil
}

func readProbeFrame[T any](r io.Reader) (T, error) {
	var zero T
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return zero, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > MaxProbeFrameBytes {
		return zero, ErrProbeRPC
	}
	raw := make([]byte, int(n))
	defer clear(raw)
	if _, err := io.ReadFull(r, raw); err != nil {
		return zero, ErrProbeRPC
	}
	value, err := schema.Decode[T](raw)
	if err != nil {
		return zero, ErrProbeRPC
	}
	return value, nil
}

// ServeProbes serializes calls on the original per-check channel. Dispatch
// checks the current Task/grant; a failed or lost reply is not retransmitted.
// Channel EOF is not evidence that a target container has stopped.
func ServeProbes(ctx context.Context, request contract.Request, channel io.ReadWriteCloser, dispatch ProbeDispatch) (outcome error) {
	defer func() {
		if recover() != nil {
			outcome = ErrProbeRPC
		}
	}()
	if ctx == nil || channel == nil || dispatch == nil || ValidateRequest(request) != nil {
		return ErrProbeRPC
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	defer channel.Close()
	stop := context.AfterFunc(ctx, func() { _ = channel.Close() })
	defer stop()
	for sequence := uint64(0); ; sequence++ {
		call, err := readProbeFrame[ProbeCall](channel)
		if err != nil {
			if errors.Is(err, io.EOF) && sequence > 0 {
				return nil
			}
			return ErrProbeRPC
		}
		if ctx.Err() != nil || !call.valid(request, sequence) {
			return ErrProbeRPC
		}
		reply := ProbeReply{Schema: 1, Binding: call.Binding, Sequence: call.Sequence, Kind: call.Kind}
		if sequence != 0 {
			operation, finish := context.WithDeadline(ctx, time.UnixMilli(call.DeadlineUnixMilli))
			var err error
			if operation.Err() != nil {
				err = operation.Err()
			} else {
				reply, err = dispatch(operation, call)
			}
			finish()
			if err != nil {
				reply = ProbeReply{Schema: 1, Binding: call.Binding, Sequence: sequence, Kind: call.Kind, Failed: true}
			}
		}
		if !reply.valid(call) || writeProbeFrame(channel, reply) != nil {
			return ErrProbeRPC
		}
		if reply.Failed {
			return ErrProbeRPC
		}
	}
}

// DispatchProbe is only typed dispatch. Pass a real GuardProbe/current native
// adapter; neither this function nor a successful reply supplies authority.
func DispatchProbe(ctx context.Context, call ProbeCall, probe contract.Probe) (ProbeReply, error) {
	r := ProbeReply{Schema: 1, Binding: call.Binding, Sequence: call.Sequence, Kind: call.Kind}
	if ctx == nil || probe == nil || ctx.Err() != nil {
		return r, ErrProbeRPC
	}
	var err error
	switch call.Kind {
	case "connect":
		if call.TCP == nil {
			return r, ErrProbeRPC
		}
		value, e := probe.Connect(ctx, *call.TCP)
		r.TCP, err = &value, e
	case "healthz":
		if call.HTTP == nil {
			return r, ErrProbeRPC
		}
		value, e := probe.Healthz(ctx, *call.HTTP)
		r.HTTP, err = &value, e
	case "exec":
		if call.Exec == nil {
			return r, ErrProbeRPC
		}
		value, e := probe.Exec(ctx, *call.Exec)
		r.Exec, err = &value, e
	case "file":
		if call.File == nil {
			return r, ErrProbeRPC
		}
		value, e := probe.File(ctx, *call.File)
		r.File, err = &value, e
	case "dependency":
		if call.Dependency == nil {
			return r, ErrProbeRPC
		}
		value, e := probe.Dependency(ctx, *call.Dependency)
		r.Dependency, err = &value, e
	default:
		return r, ErrProbeRPC
	}
	return r, err
}

type probeClient struct {
	mu       sync.Mutex
	ctx      context.Context
	request  contract.Request
	channel  net.Conn
	sequence uint64
	failed   bool
	closed   bool
}

type ProbeChannel struct{ client *probeClient }

func (p *ProbeChannel) Close() error {
	err := p.client.channel.Close()
	p.client.mu.Lock()
	p.client.closed = true
	p.client.mu.Unlock()
	return err
}

func (p *ProbeChannel) Err() error {
	p.client.mu.Lock()
	defer p.client.mu.Unlock()
	if p.client.failed {
		return ErrProbeRPC
	}
	return nil
}

// OpenProbeClient performs a per-run hello before returning opaque SDK method
// closures. Its Close is local FD closure, never a native termination receipt.
func OpenProbeClient(ctx context.Context, request contract.Request, channel net.Conn) (contract.Probe, *ProbeChannel, error) {
	if ctx == nil || channel == nil || ValidateRequest(request) != nil {
		return nil, nil, ErrProbeRPC
	}
	c := &probeClient{ctx: ctx, request: ownRequest(request), channel: channel}
	call := ProbeCall{Schema: 1, Binding: requestDigest(request), DeadlineUnixMilli: request.DeadlineUnixMilli, Kind: "hello"}
	if _, err := c.exchange(ctx, call); err != nil {
		channel.Close()
		return nil, nil, err
	}
	return opaqueCheckerProbe{healthz: c.healthz, connect: c.connect, exec: c.exec, file: c.file, dependency: c.dependency}, &ProbeChannel{client: c}, nil
}

func (c *probeClient) exchange(ctx context.Context, call ProbeCall) (ProbeReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil || c.ctx.Err() != nil || ctx.Err() != nil || c.failed || c.closed {
		return ProbeReply{}, ErrProbeRPC
	}
	deadline := time.UnixMilli(c.request.DeadlineUnixMilli)
	for _, candidate := range []context.Context{c.ctx, ctx} {
		if d, ok := candidate.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
	}
	if call.Kind != "hello" {
		c.sequence++
		call.Sequence, call.DeadlineUnixMilli = c.sequence, deadline.UnixMilli()
	}
	if c.sequence > MaxProbeCalls || c.channel.SetDeadline(deadline) != nil {
		c.failed = true
		c.channel.Close()
		return ProbeReply{}, ErrProbeRPC
	}
	stop := context.AfterFunc(ctx, func() { _ = c.channel.Close() })
	defer stop()
	stopRoot := context.AfterFunc(c.ctx, func() { _ = c.channel.Close() })
	defer stopRoot()
	if writeProbeFrame(c.channel, call) != nil {
		c.failed = true
		c.channel.Close()
		return ProbeReply{}, ErrProbeRPC
	}
	reply, err := readProbeFrame[ProbeReply](c.channel)
	if err != nil || !reply.valid(call) {
		c.failed = true
		c.channel.Close()
		return ProbeReply{}, ErrProbeRPC
	}
	if reply.Failed {
		c.failed = true
		c.channel.Close()
		return ProbeReply{}, ErrProbeRPC
	}
	return reply, nil
}

func (c *probeClient) call(kind string) ProbeCall {
	return ProbeCall{Schema: 1, Binding: requestDigest(c.request), Kind: kind}
}
func (c *probeClient) healthz(ctx context.Context, q contract.HTTPProbe) (contract.HTTPResult, error) {
	call := c.call("healthz")
	call.HTTP = &q
	r, err := c.exchange(ctx, call)
	if err != nil {
		return contract.HTTPResult{}, err
	}
	return *r.HTTP, nil
}
func (c *probeClient) connect(ctx context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
	call := c.call("connect")
	call.TCP = &q
	r, err := c.exchange(ctx, call)
	if err != nil {
		return contract.TCPResult{}, err
	}
	return *r.TCP, nil
}
func (c *probeClient) exec(ctx context.Context, q contract.ExecProbe) (contract.ExecResult, error) {
	call := c.call("exec")
	call.Exec = &q
	r, err := c.exchange(ctx, call)
	if err != nil {
		return contract.ExecResult{}, err
	}
	return *r.Exec, nil
}
func (c *probeClient) file(ctx context.Context, q contract.FileProbe) (contract.FileResult, error) {
	call := c.call("file")
	call.File = &q
	r, err := c.exchange(ctx, call)
	if err != nil {
		return contract.FileResult{}, err
	}
	return *r.File, nil
}
func (c *probeClient) dependency(ctx context.Context, q contract.DependencyProbe) (contract.DependencyResult, error) {
	call := c.call("dependency")
	call.Dependency = &q
	r, err := c.exchange(ctx, call)
	if err != nil {
		return contract.DependencyResult{}, err
	}
	return *r.Dependency, nil
}
