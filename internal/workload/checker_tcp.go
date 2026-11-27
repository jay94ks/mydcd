// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// ReadProbeTCP chooses the address from an original authorized Task. The
// script controls only its service/port and bounded request/response prefix.
func (m *Manager) ReadProbeTCP(ctx context.Context, lease ReadProbeLease, q contract.TCPProbe, authorize func(context.Context) error) (contract.TCPResult, error) {
	started := time.Now()
	phase := "authority-before"
	var stages [4]time.Duration
	defer func() {
		if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
			log.Printf("checker TCP read slow: elapsed=%s cumulative_authority_before=%s cumulative_native_before=%s cumulative_socket=%s cumulative_native_after=%s phase=%s", elapsed, stages[0], stages[1], stages[2], stages[3], phase)
		}
	}()
	if ctx == nil || authorize == nil {
		return contract.TCPResult{}, ErrPlacement
	}
	if err := authorize(ctx); err != nil {
		return contract.TCPResult{}, err
	}
	stages[0] = time.Since(started)
	phase = "native-before"
	if err := m.CheckReadProbe(ctx, lease); err != nil {
		return contract.TCPResult{}, err
	}
	stages[1] = time.Since(started)
	if !lease.Target.Status.Running {
		// This is a positive SDK observation of the same owned container,
		// not absence after a failed inspect or a Volume exit/fence proof.
		if err := authorize(ctx); err != nil || ctx.Err() != nil {
			return contract.TCPResult{}, errors.Join(err, ctx.Err())
		}
		return contract.TCPResult{Connected: false}, nil
	}
	ip := lease.Target.IPv4
	if !ip.IsValid() {
		ip = lease.Target.IPv6
	}
	phase = "socket"
	result, err := probeTCP(ctx, ip, q)
	stages[2] = time.Since(started)
	if err != nil {
		return contract.TCPResult{}, err
	}
	phase = "native-after"
	if err = m.CheckReadProbe(ctx, lease); err == nil {
		stages[3] = time.Since(started)
		phase = "authority-after"
		err = authorize(ctx)
	}
	if err != nil || ctx.Err() != nil {
		return contract.TCPResult{}, errors.Join(err, ctx.Err())
	}
	phase = "complete"
	return result, nil
}

func probeTCP(ctx context.Context, ip netip.Addr, q contract.TCPProbe) (result contract.TCPResult, err error) {
	started := time.Now()
	phase := "validate"
	var dialTime, writeTime, readTime time.Duration
	defer func() {
		if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
			log.Printf("checker TCP socket slow: elapsed=%s dial=%s write=%s read=%s phase=%s failed=%t", elapsed, dialTime, writeTime, readTime, phase, err != nil)
		}
	}()
	if ctx == nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || q.Port == 0 || q.ReadBytes < 0 || q.ReadBytes > 1<<20 || len(q.Request) > (1<<20)-q.ReadBytes {
		return contract.TCPResult{}, ErrPlacement
	}
	deadline, finite := ctx.Deadline()
	if !finite || ctx.Err() != nil {
		return contract.TCPResult{}, errors.Join(ErrPlacement, ctx.Err())
	}
	phase = "dial"
	step := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(q.Port))))
	dialTime = time.Since(step)
	if err != nil {
		if ctx.Err() == nil && errors.Is(err, syscall.ECONNREFUSED) {
			return contract.TCPResult{Connected: false}, nil
		}
		return contract.TCPResult{}, err
	}
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		return contract.TCPResult{}, err
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	if len(q.Request) != 0 {
		phase, step = "write", time.Now()
		_, err = io.Copy(conn, bytes.NewReader(q.Request))
		writeTime = time.Since(step)
		if err != nil {
			return contract.TCPResult{}, err
		}
	}
	var data []byte
	if q.ReadBytes != 0 {
		data = make([]byte, q.ReadBytes)
		phase, step = "read", time.Now()
		_, err = io.ReadFull(conn, data)
		readTime = time.Since(step)
		if err != nil {
			return contract.TCPResult{}, err
		}
	}
	if ctx.Err() != nil {
		return contract.TCPResult{}, ctx.Err()
	}
	phase = "complete"
	return contract.TCPResult{Connected: true, Data: data}, nil
}
