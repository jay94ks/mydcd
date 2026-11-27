// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// Test inputs only: real kernel sockets inside the managed nonroot workload.
// This executable never forwards IP packets or decides Seafield Cluster route authority.
func routeMode(args []string) (bool, error) {
	if len(args) > 1 && args[1] == "--route-dns" {
		return true, routeDNSProbe(args[2:])
	}
	if len(args) > 1 && args[1] == "--route-probe" {
		if len(args) != 5 {
			return true, fmt.Errorf("route probe requires protocol, numeric destination and local port")
		}
		target, err := netip.ParseAddrPort(args[3])
		local, portErr := strconv.ParseUint(args[4], 10, 16)
		if err != nil || portErr != nil || local < 1024 || target.Port() == 0 || target.Addr().IsUnspecified() || target.Addr().IsMulticast() {
			return true, fmt.Errorf("invalid numeric route probe")
		}
		dialer := net.Dialer{Timeout: 10 * time.Second}
		if args[2] == "tcp" {
			dialer.LocalAddr = &net.TCPAddr{Port: int(local)}
		} else if args[2] == "udp" {
			dialer.LocalAddr = &net.UDPAddr{Port: int(local)}
		} else {
			return true, fmt.Errorf("TCP or UDP required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(ctx, args[2], target.String())
		if err != nil {
			return true, routeSocketError(err)
		}
		defer conn.Close()
		if tcp, ok := conn.(*net.TCPConn); ok {
			if err := tcp.SetLinger(0); err != nil {
				return true, err
			}
		} // Explicit RST input; no long TIME_WAIT fixture delay.
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return true, err
		}
		payload := []byte(fmt.Sprintf("sfc-route-%s-%d", args[2], local))
		if _, err := conn.Write(payload); err != nil {
			return true, routeSocketError(err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, response); err != nil {
			return true, routeSocketError(err)
		}
		if !bytes.Equal(payload, response) {
			return true, fmt.Errorf("route echo changed data")
		}
		fmt.Println("route echo verified", args[2], target, local)
		return true, nil
	}
	if len(args) < 2 || args[1] != "--route-serve" {
		return false, nil
	}
	if len(args) != 2 {
		return true, fmt.Errorf("route server takes no additional arguments")
	}
	closeListeners, err := startRouteEchoListeners()
	if err != nil {
		return true, err
	}
	defer closeListeners()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	<-ctx.Done()
	return true, nil
}

// Reuse the same bounded backend echo sockets alongside HTTP for direct
// Docker publishing. This is fixture input, not another runtime or forwarder.
func startRouteEchoListeners() (closeListeners func(), err error) {
	var listeners []net.Listener
	var datagrams []*net.UDPConn
	closeListeners = func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		for _, socket := range datagrams {
			_ = socket.Close()
		}
	}
	defer func(closeOwned func()) {
		if err != nil {
			closeOwned()
		}
	}(closeListeners)
	slots := make(chan struct{}, 8)
	for _, port := range []string{"33100", "33101"} {
		listener, err := net.Listen("tcp", ":"+port)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				select {
				case slots <- struct{}{}:
				default:
					_ = conn.Close()
					continue
				}
				go func() {
					defer func() { _ = conn.Close(); <-slots }()
					_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
					fmt.Fprintln(os.Stdout, "route peer tcp", conn.RemoteAddr())
					_, _ = io.Copy(conn, io.LimitReader(conn, 1024))
				}()
			}
		}()
	}
	for _, port := range []int{53100, 53101} {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err != nil {
			return nil, err
		}
		datagrams = append(datagrams, socket)
		go func() {
			data := make([]byte, 1024)
			for {
				n, peer, err := socket.ReadFromUDP(data)
				if err != nil {
					return
				}
				fmt.Fprintln(os.Stdout, "route peer udp", peer)
				_, _ = socket.WriteToUDP(data[:n], peer)
			}
		}()
	}
	fmt.Fprintln(os.Stdout, "route TCP/UDP listeners ready")
	return closeListeners, nil
}

func routeSocketError(err error) error {
	var socket net.Error
	if errors.As(err, &socket) && socket.Timeout() {
		return fmt.Errorf("route socket timeout: %w", err)
	}
	return err
}
