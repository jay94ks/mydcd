// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jay94ks/seafield/tests/servicecallfixture"
)

func readServiceCallFixtureBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, (256<<10)+1))
	if err != nil || len(body) > 256<<10 {
		http.Error(w, "bad fixture request", 400)
		return nil, false
	}
	return body, true
}

// Opt-in owned native input, independent of the product service-call engine.
func serviceCallFixtureMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/call", func(w http.ResponseWriter, r *http.Request) {
		body, ok := readServiceCallFixtureBody(w, r)
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "must-not-escape")
		fmt.Fprintf(w, "%d:%x", len(body), sha256.Sum256(body))
	})
	mux.HandleFunc("/call-large", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := readServiceCallFixtureBody(w, r); !ok {
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("x", (64<<10)+1))
	})
	mux.HandleFunc("/call-redirect", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := readServiceCallFixtureBody(w, r); !ok {
			return
		}
		http.Redirect(w, r, "/call", http.StatusFound)
	})
	return mux
}

func startServiceCallFixture() (func(), error) {
	mux := serviceCallFixtureMux()
	for _, path := range []string{"/call", "/call-large", "/call-redirect"} {
		http.Handle(path, mux)
	}
	raw, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var addresses []net.IP
	for _, address := range raw {
		ip, _, e := net.ParseCIDR(address.String())
		if e == nil && !ip.IsLoopback() {
			addresses = append(addresses, ip)
		}
	}
	pair, err := servicecallfixture.Certificate(addresses)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		return nil, err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		if err := server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}})); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	return func() { _ = server.Close() }, nil
}
