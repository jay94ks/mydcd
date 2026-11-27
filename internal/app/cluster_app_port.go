// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// clusterAppPort is node.yaml cluster_apps.<app>.port: a TCP port on the
// server's own address that sfcd forwards to the app's web port while
// this server runs the app. It is the first way in before any ingress
// route and works apart from ingress; removing port closes it.
type clusterAppPort struct {
	mu     sync.Mutex
	listen string
	target string
	ln     net.Listener
	conns  sync.WaitGroup
}

// set opens listen forwarding to target, or closes it ("" listen).
// Calling it again with the same values keeps the open listener.
func (p *clusterAppPort) set(listen string, target netip.AddrPort) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	want := ""
	if target.IsValid() {
		want = target.String()
	}
	if p.ln != nil && p.listen == listen && p.target == want && listen != "" {
		return nil
	}
	p.closeLocked()
	if listen == "" || want == "" {
		return nil
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	p.ln, p.listen, p.target = ln, listen, want
	go p.serve(ln, want)
	return nil
}

func (p *clusterAppPort) serve(ln net.Listener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("cluster app port: accept stopped")
			}
			return
		}
		p.conns.Add(1)
		go func() {
			defer p.conns.Done()
			forward(c, target)
		}()
	}
}

// forward copies both ways between the client and the app.
func forward(c net.Conn, target string) {
	defer c.Close()
	d := net.Dialer{Timeout: 5 * time.Second}
	u, err := d.Dial("tcp", target)
	if err != nil {
		return
	}
	defer u.Close()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(u, c)
	go pipe(c, u)
	<-done
	<-done
}

func (p *clusterAppPort) closeLocked() {
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln, p.listen, p.target = nil, "", ""
	}
}

// close stops listening. Open connections end on their own.
func (p *clusterAppPort) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}

// clusterAppListen is listen's host with port: the server's own address.
func clusterAppListen(nodeListen string, port uint16) string {
	host, _, err := net.SplitHostPort(nodeListen)
	if err != nil || port == 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
