// SPDX-License-Identifier: Apache-2.0

package provlog

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MaxBody is how much of a request or response body an entry keeps.
const MaxBody = 4 << 10

type opKey struct{}

// WithOp names the adapter operation of the requests made with ctx.
func WithOp(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, opKey{}, op)
}

// OpOf returns the operation named by WithOp.
func OpOf(ctx context.Context) string {
	s, _ := ctx.Value(opKey{}).(string)
	return s
}

// Source says who logs through a Transport.
type Source struct {
	Provider string // "dns:hostinger"
	Conn     string
	// Redact rewrites a body before it is kept (after the generic
	// redaction). isReq is true for the request body. Nil keeps the body
	// as Redact returns it.
	Redact func(body []byte, isReq bool) string
	// Headers are response headers worth keeping (canonical names).
	Headers []string
	// Classify turns a status (and body) into an error kind for the entry;
	// nil leaves Kind empty.
	Classify func(status int, body []byte) string
}

// Transport wraps base (nil: http.DefaultTransport) and logs every
// request to l with s. Authorization and cookies are never logged.
func Transport(base http.RoundTripper, l *Log, s Source) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base, l: l, s: s}
}

type transport struct {
	base http.RoundTripper
	l    *Log
	s    Source
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.l.Enabled() {
		return t.base.RoundTrip(req)
	}
	var reqBody []byte
	if req.Body != nil && req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			reqBody, _ = io.ReadAll(io.LimitReader(rc, 1<<20))
			rc.Close()
		}
	}
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	h := &HTTP{Method: req.Method, URL: SafeURL(req.URL), DurationMS: time.Since(start).Milliseconds(), ReqBytes: len(reqBody)}
	if len(reqBody) > 0 {
		h.Request = t.body(reqBody, true)
	}
	e := Entry{Provider: t.s.Provider, Conn: t.s.Conn, Op: OpOf(req.Context()), HTTP: h}
	if err != nil {
		e.Level, e.Error = Error, Scrub(err.Error())
		t.l.Add(e)
		return nil, err
	}
	h.Status = resp.StatusCode
	// keep a copy of the body for the log and give the caller the same bytes
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	if rerr != nil {
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(respBody), errReader{rerr}))
		e.Error = Scrub(rerr.Error())
	}
	h.RespBytes = len(respBody)
	h.Response = t.body(respBody, false)
	for _, name := range append([]string{"Content-Type", "Retry-After", "Ratelimit", "Ratelimit-Policy", "Ratelimit-Remaining", "Ratelimit-Reset", "X-Correlation-Id"}, t.s.Headers...) {
		if v := resp.Header.Get(name); v != "" {
			if h.Headers == nil {
				h.Headers = map[string]string{}
			}
			h.Headers[name] = Truncate(Scrub(v), 200)
		}
	}
	switch {
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		e.Level = Error
	case resp.StatusCode >= 400:
		e.Level = Warn
	}
	if t.s.Classify != nil && resp.StatusCode >= 400 {
		e.Kind = t.s.Classify(resp.StatusCode, respBody)
	}
	t.l.Add(e)
	return resp, nil
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func (t *transport) body(b []byte, isReq bool) string {
	var s string
	if t.s.Redact != nil {
		s = t.s.Redact(b, isReq)
	} else {
		s = string(b)
	}
	return Truncate(Scrub(s), MaxBody)
}

var secretQuery = regexp.MustCompile(`(?i)token|key|secret|password|auth|sig`)

// SafeURL is u without user info and with secret-looking query values
// replaced.
func SafeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	if c.RawQuery != "" {
		q := c.Query()
		for k := range q {
			if secretQuery.MatchString(k) {
				q[k] = []string{"REDACTED"}
			}
		}
		c.RawQuery = q.Encode()
	}
	return c.String()
}

var scrubRE = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`(?i)("[^"]*` + secretName + `[^"]*"\s*:\s*)"(?:[^"\\]|\\.)*"`),
	regexp.MustCompile(`(?i)((?:^|&)[^=&\s]*` + secretName + `[^=&\s]*=)[^&\s]*`),
}

// secretName matches field names that hold secrets ("access_token",
// "client_secret", "apiToken", "x-api-key", "hmacKey", …).
const secretName = `(?:token|secret|passw|api[_-]?key|private[_-]?key|hmac|credential)`

// Scrub removes bearer tokens, private keys, and the values of JSON and
// form fields whose names look secret (secretName) from s. Adapters
// redact what they know about first; this is the net under it.
func Scrub(s string) string {
	s = scrubRE[0].ReplaceAllString(s, "${1}REDACTED")
	s = scrubRE[1].ReplaceAllString(s, "[private key removed]")
	s = scrubRE[2].ReplaceAllString(s, `${1}"REDACTED"`)
	if t := strings.TrimSpace(s); t != "" && t[0] != '{' && t[0] != '[' {
		s = scrubRE[3].ReplaceAllString(s, "${1}REDACTED")
	}
	return s
}

// Truncate cuts s to n bytes (on a rune boundary) and says how much was
// cut.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…[" + strconv.Itoa(len(s)-cut) + " bytes cut]"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
