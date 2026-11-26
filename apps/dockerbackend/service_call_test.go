// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fixtureBodyWitness struct {
	io.ReadCloser
	read int
}

func (r *fixtureBodyWitness) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.read += n
	return n, err
}

type fixtureResponseWitness struct {
	http.ResponseWriter
	body *fixtureBodyWitness
	t    *testing.T
}

func (w fixtureResponseWitness) check() {
	if w.body.read != 256<<10 {
		w.t.Errorf("fixture responded before accepting its full POST: %d bytes", w.body.read)
	}
}
func (w fixtureResponseWitness) WriteHeader(status int) {
	w.check()
	w.ResponseWriter.WriteHeader(status)
}
func (w fixtureResponseWitness) Write(p []byte) (int, error) {
	w.check()
	return w.ResponseWriter.Write(p)
}

func TestServiceFixtureRespondsAfterConsumingMaximumPOST(t *testing.T) {
	mux := serviceCallFixtureMux()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := &fixtureBodyWitness{ReadCloser: r.Body}
		r.Body = body
		mux.ServeHTTP(fixtureResponseWitness{ResponseWriter: w, body: body, t: t}, r)
	}))
	defer server.Close()
	defer server.CloseClientConnections()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/call-large", "/call-redirect"} {
		t.Run(path, func(t *testing.T) {
			response, err := client.Post(server.URL+path, "application/octet-stream", bytes.NewReader(make([]byte, 256<<10)))
			if err != nil {
				t.Fatal("fixture response interrupted by unread request", err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal("fixture response truncated", err)
			}
			if path == "/call-large" && (response.StatusCode != 200 || len(body) != (64<<10)+1) || path == "/call-redirect" && response.StatusCode != 302 {
				t.Fatal("fixture did not deliver intended response", response.StatusCode, len(body))
			}
		})
	}
}
