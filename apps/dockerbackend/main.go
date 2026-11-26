// SPDX-License-Identifier: Apache-2.0

// dockerbackend is a static, local-only Engine/Ingress boundary fixture.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func tmpfsProbe() bool {
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, want := range []struct {
		path           string
		uid, gid, mode uint32
	}{{"/scratch", 10001, 10001, 0700}, {"/runtime", 0, 0, 01777}} {
		var fs syscall.Statfs_t
		var stat syscall.Stat_t
		if syscall.Statfs(want.path, &fs) != nil || uint64(fs.Type) != 0x01021994 || fs.Blocks*uint64(fs.Bsize) != 4<<20 || syscall.Stat(want.path, &stat) != nil || stat.Uid != want.uid || stat.Gid != want.gid || stat.Mode&07777 != want.mode {
			return false
		}
		found := false
		for _, line := range strings.Split(string(info), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 6 && fields[4] == want.path {
				flags := "," + fields[5] + ","
				found = strings.Contains(flags, ",nosuid,") && strings.Contains(flags, ",nodev,") && strings.Contains(flags, ",noexec,")
			}
		}
		if !found {
			return false
		}
		name := filepath.Join(want.path, ".probe")
		if os.WriteFile(name, []byte("tmpfs-probe"), 0600) != nil {
			return false
		}
		if os.Remove(name) != nil {
			return false
		}
	}
	return true
}

func volumePaths() []string {
	if os.Getenv("MYDC_VOLUME_SECOND_FIXTURE") == "1" {
		return []string{"/data", "/logs"}
	}
	return []string{"/data"}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--build-cancel-fixture" {
		// The owned native BuildKit cancellation test waits for this public
		// RUN output before cancelling its original job. This finite fixture
		// needs no shell, child process or independently managed daemon.
		fmt.Fprintln(os.Stdout, "owned-build-cancel-ready")
		time.Sleep(10 * time.Minute)
		return
	}
	if handled, err := buildFixture(os.Args); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if execFixture(os.Args) {
		return
	}
	if os.Getenv("MYDC_OBSERVATION_FIXTURE") == "1" {
		fmt.Fprintln(os.Stdout, "mydc-observation-stdout")
		fmt.Fprintln(os.Stderr, "mydc-observation-stderr")
		http.HandleFunc("/logburst", func(w http.ResponseWriter, r *http.Request) {
			marker := r.URL.Query().Get("marker")
			if r.Method != http.MethodPost || len(marker) < 1 || len(marker) > 64 || strings.ContainsAny(marker, "\x00\r\n ") {
				http.Error(w, "invalid owned log fixture input", http.StatusBadRequest)
				return
			}
			for j := 0; j < 32; j++ {
				fmt.Fprintf(os.Stdout, "%s-%03d:%s\n", marker, j, strings.Repeat("L", 4000))
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	if handled, err := routeMode(os.Args); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if errors.Is(err, errRouteDNSTimeout) {
				os.Exit(2)
			}
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--exit-code" {
		code, err := strconv.Atoi(os.Args[2])
		if err != nil || code < 0 || code > 255 {
			os.Exit(2)
		}
		os.Exit(code)
	}
	if len(os.Args) == 3 && os.Args[1] == "--shutdown-delay" {
		delay, err := time.ParseDuration(os.Args[2])
		if err != nil || delay < 0 || delay > time.Hour {
			os.Exit(2)
		}
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGTERM, syscall.SIGQUIT)
		go func() {
			<-stop
			time.Sleep(delay)
			os.Exit(0)
		}()
	}
	if os.Getenv("MYDC_DNS_FIXTURE") == "1" {
		http.HandleFunc("/dns-query", dnsQuery)
		http.HandleFunc("/identity", func(w http.ResponseWriter, r *http.Request) {
			hostname, err := os.Hostname()
			if err != nil {
				http.Error(w, "fixture hostname unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, "{\"Hostname\":%q,\"Revision\":%q}", hostname, os.Getenv("REVISION"))
		})
		http.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
			name := r.URL.Query().Get("name")
			if name == "" || len(name) > 253 {
				http.Error(w, "invalid name", http.StatusBadRequest)
				return
			}
			resolver := &net.Resolver{PreferGo: true}
			if r.URL.Query().Get("transport") == "tcp" {
				resolver.Dial = func(ctx context.Context, _, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", address)
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			hosts, err := resolver.LookupHost(ctx, name)
			if err != nil {
				http.Error(w, "lookup failed", http.StatusBadGateway)
				return
			}
			fmt.Fprint(w, strings.Join(hosts, ","))
		})
	}
	if len(os.Args) == 2 && (os.Args[1] == "--volume-exit=clean" || os.Args[1] == "--volume-exit=137") {
		// This mode supplies an actual writer's clean/nonzero process exit to
		// the activation boundary test. It does not emulate a database.
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGTERM)
		defer signal.Stop(stop)
		file, err := os.OpenFile("/data/exit-marker", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
		if err != nil {
			os.Exit(2)
		}
		_, err = file.WriteString(os.Args[1])
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			os.Exit(2)
		}
		<-stop
		if os.Args[1] == "--volume-exit=137" {
			os.Exit(137)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--tcp-probe" {
		host, _, err := net.SplitHostPort(os.Args[2])
		if err != nil || net.ParseIP(host) == nil {
			os.Exit(2)
		}
		conn, err := net.DialTimeout("tcp", os.Args[2], 750*time.Millisecond)
		if err != nil {
			os.Exit(1)
		}
		_ = conn.Close()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--volume-probe" {
		for _, dir := range volumePaths() {
			data, err := os.ReadFile(filepath.Join(dir, "marker"))
			if err != nil || string(data) != "volume-original" || os.Geteuid() != 10001 {
				os.Exit(1)
			}
		}

		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--tmpfs-probe" {
		if !tmpfsProbe() {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--projection-probe" {
		path := os.Getenv("MYDC_PROJECTION_FILE")
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, []byte("private-db-value")) {
			os.Exit(1)
		}
		clear(data)
		if os.Getenv("MYDC_SECRET_LOG_FIXTURE") == "1" && os.Getenv("MYDC_SECRET_ENV_VALUE") != "private-db-value" {
			os.Exit(1)
		}
		// The owner could chmod a writable bind. A read-only mount must reject
		// it even though the file UID matches this nonroot process.
		if os.Chmod(path, 0600) == nil {
			os.Exit(1)
		}
		return
	}
	secretLogFixture()
	if len(os.Args) == 2 && os.Args[1] == "--probe" {
		client := http.Client{Timeout: 500 * time.Millisecond}
		response, err := client.Get("http://127.0.0.1:8080/ping")
		if err != nil {
			os.Exit(1)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--volume-readonly-probe" {
		for _, dir := range volumePaths() {
			file, err := os.OpenFile(filepath.Join(dir, ".mydc-readonly-probe"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				_ = file.Close()
				_ = os.Remove(filepath.Join(dir, ".mydc-readonly-probe"))
				os.Exit(1)
			}
			if !errors.Is(err, syscall.EROFS) {
				os.Exit(1)
			}
		}
		return
	}
	if os.Getenv("MYDC_PUBLISHED_PORTS_FIXTURE") == "1" {
		closeListeners, err := startRouteEchoListeners()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer closeListeners()
	}
	if os.Getenv("MYDC_VOLUME_FIXTURE") == "1" {
		for _, dir := range volumePaths() {
			data, err := os.ReadFile(filepath.Join(dir, "marker"))
			if os.IsNotExist(err) {
				err = os.WriteFile(filepath.Join(dir, "marker"), []byte("volume-original"), 0600)
			} else if err == nil && string(data) != "volume-original" {
				os.Exit(1)
			}
			if err != nil || os.Geteuid() != 10001 {
				fmt.Fprintln(os.Stderr, "volume fixture initialization:", err, "euid:", os.Geteuid())
				os.Exit(1)
			}
		}

	}
	registerMoveFixture()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "mydc-boundary "+r.URL.RequestURI()) })
	http.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "mydc-boundary "+r.URL.RequestURI()) })
	if tenant := os.Getenv("MYDC_TENANT_FIXTURE"); tenant != "" {
		http.HandleFunc("/tenant", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tenant) })
	}
	if os.Getenv("MYDC_READINESS_FIXTURE") == "1" {
		var ready atomic.Bool
		ready.Store(true)
		http.HandleFunc("/readiness-state", func(w http.ResponseWriter, r *http.Request) {
			ready.Store(r.URL.Query().Get("ready") == "1")
			w.WriteHeader(http.StatusNoContent)
		})
		http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			if !ready.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
	}
	if os.Getenv("MYDC_TMPFS_FIXTURE") == "1" {
		http.HandleFunc("/tmpfs-state", func(w http.ResponseWriter, r *http.Request) {
			const marker = "/scratch/original-marker"
			if r.URL.Query().Get("write") == "1" {
				if err := os.WriteFile(marker, []byte("original"), 0600); err != nil {
					http.Error(w, "write failed", 500)
					return
				}
			}
			data, err := os.ReadFile(marker)
			switch {
			case os.IsNotExist(err):
				fmt.Fprint(w, "missing")
			case err == nil && string(data) == "original":
				fmt.Fprint(w, "present")
			default:
				http.Error(w, "read failed", 500)
			}
		})
	}
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	http.HandleFunc("/upgrade", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "mydc-echo" {
			http.Error(w, "upgrade required", 426)
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: mydc-echo\r\n\r\n")
		rw.Flush()
		io.Copy(c, rw)
	})
	if os.Getenv("MYDC_SERVICE_CALL_FIXTURE") == "1" {
		closeFixture, err := startServiceCallFixture()
		if err != nil {
			panic(err)
		}
		defer closeFixture()
	}
	s := http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	if os.Getenv("MYDC_GRACEFUL_FIXTURE") == "1" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		done := make(chan error, 1)
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done <- s.Shutdown(shutdown)
		}()
		if err := s.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
		if err := <-done; err != nil {
			panic(err)
		}
		return
	}
	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}
}

// Test-only wire client runs INSIDE the actual nonroot workload. Product code
// never calls this endpoint; it allows transport/EDNS/framing counterexamples
// without pretending that a host packet has a workload's native provenance.
func dnsQuery(w http.ResponseWriter, r *http.Request) {
	server := r.URL.Query().Get("server")
	host, port, err := net.SplitHostPort(server)
	protocol := r.URL.Query().Get("transport")
	if r.Method != "POST" || err != nil || net.ParseIP(host) == nil || port != "53" || protocol != "udp" && protocol != "tcp" {
		http.Error(w, "invalid DNS fixture input", 400)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil || len(raw) < 12 {
		http.Error(w, "invalid DNS wire", 400)
		return
	}
	budget := 3 * time.Second
	if value := r.URL.Query().Get("timeout_ms"); value != "" {
		milliseconds, err := strconv.Atoi(value)
		if err != nil || milliseconds < 100 || milliseconds > 15000 {
			http.Error(w, "invalid DNS fixture deadline", 400)
			return
		}
		budget = time.Duration(milliseconds) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, protocol, server)
	if err != nil {
		http.Error(w, "DNS connect", 502)
		return
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	packet := raw
	if protocol == "tcp" {
		packet = make([]byte, 2+len(raw))
		binary.BigEndian.PutUint16(packet, uint16(len(raw)))
		copy(packet[2:], raw)
	}
	for len(packet) > 0 {
		part := packet
		if protocol == "tcp" && r.URL.Query().Get("fragment") == "1" {
			part = packet[:min(len(packet), 3)]
		}
		count, e := conn.Write(part)
		if e != nil || count == 0 {
			http.Error(w, "DNS write", 502)
			return
		}
		packet = packet[count:]
	}
	if protocol == "tcp" && r.URL.Query().Get("half_close") == "1" {
		if c, ok := conn.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}
	var response []byte
	if protocol == "tcp" {
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err == nil {
			response = make([]byte, int(binary.BigEndian.Uint16(size[:])))
			_, err = io.ReadFull(conn, response)
		}
	} else {
		response = make([]byte, 65535)
		var n int
		n, err = conn.Read(response)
		response = response[:n]
	}
	if err != nil {
		http.Error(w, "DNS read", 502)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(response)
}
