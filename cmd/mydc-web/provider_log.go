// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jay94ks/mydcd/internal/web/provlog"
)

const providerLogUsage = `usage: mydc-web provider-log [flags]

Reads the provider diagnostic log (DNS vendors, ACME certificate
authorities) of a running mydc-web. Turn the log on in 웹 앱 설정 first; it
shows a temporary token. Pass it with -token-file or MYDC_WEB_DIAG_TOKEN
(-token also works but stays in shell history).

  mydc-web provider-log -url https://web.example -tail 200
  mydc-web provider-log -url https://web.example -follow -out log.jsonl
  mydc-web provider-log -url https://web.example -format summary -provider dns:

Flags:
`

// providerLogTool is the debugging tool: poll (default), follow over SSE,
// or summarize. It returns the exit code.
func providerLogTool(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("provider-log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, providerLogUsage); fs.PrintDefaults() }
	base := fs.String("url", "http://127.0.0.1:8080", "mydc-web address")
	token := fs.String("token", "", "bearer token (prefer -token-file or MYDC_WEB_DIAG_TOKEN)")
	tokenFile := fs.String("token-file", "", "file holding the bearer token")
	insecure := fs.Bool("insecure", false, "skip TLS certificate checks (a self-signed web certificate)")
	follow := fs.Bool("follow", false, "keep reading new entries over SSE (reconnects without gaps)")
	after := fs.Uint64("after", 0, "only entries after this seq")
	tail := fs.Int("tail", 0, "only the newest n entries (not with -after)")
	format := fs.String("format", "jsonl", "jsonl, text or summary")
	out := fs.String("out", "", "append entries to this file instead of stdout")
	provider := fs.String("provider", "", `provider ("dns:hostinger", or a prefix like "acme:")`)
	op := fs.String("op", "", "operation (GetZone, Apply, NewOrder, …)")
	level := fs.String("level", "", "minimum level: info, warn or error")
	since := fs.Duration("since", 0, "only entries newer than this (e.g. 2h)")
	text := fs.String("q", "", "only entries containing this text")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tok := strings.TrimSpace(*token)
	if tok == "" && *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		tok = strings.TrimSpace(getenv("MYDC_WEB_DIAG_TOKEN"))
	}
	if tok == "" {
		fmt.Fprintln(stderr, "no token: turn the provider log on in 웹 앱 설정 and pass the token it shows")
		return 2
	}
	if *format != "jsonl" && *format != "text" && *format != "summary" {
		fmt.Fprintln(stderr, "-format must be jsonl, text or summary")
		return 2
	}
	if *follow && *format == "summary" {
		fmt.Fprintln(stderr, "-format summary does not work with -follow")
		return 2
	}
	q := url.Values{}
	for k, v := range map[string]string{"provider": *provider, "op": *op, "level": *level, "q": *text} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if *since > 0 {
		q.Set("since", time.Now().Add(-*since).UTC().Format(time.RFC3339))
	}
	w := stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer f.Close()
		w = f
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if *insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	c := &plClient{base: strings.TrimRight(*base, "/"), token: tok, http: &http.Client{Transport: tr}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var sum *plSummary
	if *format == "summary" {
		sum = &plSummary{}
	}
	emit := func(e provlog.Entry) error {
		switch {
		case sum != nil:
			sum.add(e)
			return nil
		case *format == "text":
			_, err := fmt.Fprintln(w, textLine(e))
			return err
		}
		raw, _ := json.Marshal(e)
		_, err := fmt.Fprintf(w, "%s\n", raw)
		return err
	}

	cursor := *after
	if *tail > 0 {
		qq := cloneValues(q)
		qq.Set("tail", strconv.Itoa(*tail))
		res, err := c.list(ctx, qq)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		for _, e := range res.Page.Entries {
			if err := emit(e); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		cursor = res.Page.Last
		fmt.Fprintln(stderr, stateLine(res.State))
	} else {
		for {
			qq := cloneValues(q)
			qq.Set("after", strconv.FormatUint(cursor, 10))
			qq.Set("limit", "1000")
			res, err := c.list(ctx, qq)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			for _, e := range res.Page.Entries {
				if err := emit(e); err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
			}
			cursor = res.Page.Next
			if !res.Page.More {
				fmt.Fprintln(stderr, stateLine(res.State))
				break
			}
		}
	}
	if sum != nil {
		sum.write(stdout)
		return 0
	}
	if !*follow {
		return 0
	}
	if err := c.follow(ctx, q, cursor, emit, stderr); err != nil && ctx.Err() == nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

type plClient struct {
	base, token string
	http        *http.Client
}

type plList struct {
	Page  provlog.Page  `json:"page"`
	State provlog.State `json:"state"`
}

var errTokenExpired = errors.New("the token is wrong or expired: turn the provider log on again in 웹 앱 설정")

func (c *plClient) get(ctx context.Context, path string, q url.Values, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", accept)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, errTokenExpired
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return resp, nil
}

func (c *plClient) list(ctx context.Context, q url.Values) (plList, error) {
	var out plList
	resp, err := c.get(ctx, "/api/v1/diag/provider-log", q, "application/json")
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// follow reads the SSE stream from cursor and reconnects (with the last
// seq) when it drops, until ctx ends or the token expires.
func (c *plClient) follow(ctx context.Context, q url.Values, cursor uint64, emit func(provlog.Entry) error, stderr io.Writer) error {
	backoff := time.Second
	for {
		qq := cloneValues(q)
		qq.Set("after", strconv.FormatUint(cursor, 10))
		resp, err := c.get(ctx, "/api/v1/diag/provider-log/stream", qq, "text/event-stream")
		if errors.Is(err, errTokenExpired) {
			return err
		}
		if err == nil {
			backoff = time.Second
			var expired bool
			cursor, expired, err = readSSE(resp.Body, cursor, emit, stderr)
			resp.Body.Close()
			if expired {
				fmt.Fprintln(stderr, "collection turned off (idle for an hour, or turned off in 웹 앱 설정)")
				return nil
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		fmt.Fprintf(stderr, "stream dropped (%v); reconnecting from seq %d\n", err, cursor)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func readSSE(r io.Reader, cursor uint64, emit func(provlog.Entry) error, stderr io.Writer) (uint64, bool, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var event, data string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			switch event {
			case "entry":
				var e provlog.Entry
				if err := json.Unmarshal([]byte(data), &e); err == nil {
					if err := emit(e); err != nil {
						return cursor, false, err
					}
					cursor = max(cursor, e.Seq)
				}
			case "state":
				var st provlog.State
				if json.Unmarshal([]byte(data), &st) == nil {
					fmt.Fprintln(stderr, stateLine(st))
				}
			case "expired":
				return cursor, true, nil
			}
			event, data = "", ""
		case strings.HasPrefix(line, "event: "):
			event = line[len("event: "):]
		case strings.HasPrefix(line, "data: "):
			data += line[len("data: "):]
		}
	}
	err := sc.Err()
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return cursor, false, err
}

func stateLine(st provlog.State) string {
	if !st.Enabled {
		return fmt.Sprintf("provider log: off (%s), newest seq %d", st.DisabledReason, st.Last)
	}
	return fmt.Sprintf("provider log: on since %s by %s, turns off at %s if idle, newest seq %d",
		st.EnabledAt.Local().Format(time.DateTime), st.EnabledBy, st.ExpiresAt.Local().Format(time.DateTime), st.Last)
}

func textLine(e provlog.Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d %s %-5s %s", e.Seq, e.At.Local().Format("01-02 15:04:05"), e.Level, e.Provider)
	if e.Conn != "" {
		b.WriteString("/" + e.Conn)
	}
	if e.Op != "" {
		b.WriteString(" " + e.Op)
	}
	if h := e.HTTP; h != nil {
		fmt.Fprintf(&b, " %s %s → %d (%dms)", h.Method, h.URL, h.Status, h.DurationMS)
	}
	if e.Msg != "" {
		b.WriteString(" " + e.Msg)
	}
	if e.Kind != "" {
		b.WriteString(" kind=" + e.Kind)
	}
	if e.Error != "" {
		b.WriteString(" error=" + e.Error)
	}
	if h := e.HTTP; h != nil && h.Status >= 400 && h.Response != "" {
		b.WriteString("\n    response: " + h.Response)
	}
	return b.String()
}

// plSummary counts calls per provider and operation and keeps the newest
// failures, for a first look.
type plSummary struct {
	rows     map[string]*plRow
	failures []provlog.Entry
	first    time.Time
	last     time.Time
	n        int
}

type plRow struct {
	calls, warn, errs int
	status            map[int]int
	ms                int64
}

func (s *plSummary) add(e provlog.Entry) {
	if s.rows == nil {
		s.rows = map[string]*plRow{}
	}
	if s.n == 0 {
		s.first = e.At
	}
	s.n++
	s.last = e.At
	key := e.Provider + " " + e.Op
	r := s.rows[key]
	if r == nil {
		r = &plRow{status: map[int]int{}}
		s.rows[key] = r
	}
	r.calls++
	switch e.Level {
	case provlog.Warn:
		r.warn++
	case provlog.Error:
		r.errs++
	}
	if e.HTTP != nil {
		r.status[e.HTTP.Status]++
		r.ms += e.HTTP.DurationMS
	}
	if e.Level != provlog.Info {
		s.failures = append(s.failures, e)
		if len(s.failures) > 20 {
			s.failures = s.failures[1:]
		}
	}
}

func (s *plSummary) write(w io.Writer) {
	if s.n == 0 {
		fmt.Fprintln(w, "no entries")
		return
	}
	fmt.Fprintf(w, "%d entries, %s … %s\n\n", s.n, s.first.Local().Format(time.DateTime), s.last.Local().Format(time.DateTime))
	keys := make([]string, 0, len(s.rows))
	for k := range s.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "%-48s %6s %5s %5s %7s  %s\n", "provider op", "calls", "warn", "error", "avg ms", "statuses")
	for _, k := range keys {
		r := s.rows[k]
		var st []string
		for code, n := range r.status {
			st = append(st, fmt.Sprintf("%d×%d", code, n))
		}
		sort.Strings(st)
		avg := int64(0)
		if r.calls > 0 {
			avg = r.ms / int64(r.calls)
		}
		fmt.Fprintf(w, "%-48s %6d %5d %5d %7d  %s\n", k, r.calls, r.warn, r.errs, avg, strings.Join(st, " "))
	}
	if len(s.failures) > 0 {
		fmt.Fprintf(w, "\nnewest %d warnings and errors:\n", len(s.failures))
		for _, e := range s.failures {
			fmt.Fprintln(w, textLine(e))
		}
	}
}
