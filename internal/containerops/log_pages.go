// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

const MaxLogWindowBytes = 8 << 20
const LogWindowSeconds = 10 * 60
const maxLogWindows = 16
const maxLogPageBytes = 64 << 20

var ErrLogCursorExpired = errors.New("CURSOR_EXPIRED")
var ErrLogWindowLimit = errors.New("LOG_WINDOW_LIMIT")
var ErrLogCursorCapacity = errors.New("LOG_CURSOR_CAPACITY")

func validReadWindowScope(user string, nonce [32]byte, at int64) bool {
	return user != "" && nonce != ([32]byte{}) && at > 0 && at <= int64(^uint64(0)>>1)-LogWindowSeconds
}

func parseLogCursor(cursor string) (string, int, bool) {
	id, after, ok := strings.Cut(cursor, ":")
	if !ok || len(id) != 64 || strings.ToLower(id) != id || len(after) > 8 {
		return "", 0, false
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 32 || bytes.Equal(decoded, make([]byte, 32)) {
		return "", 0, false
	}
	offset, err := strconv.Atoi(after)
	return id, offset, err == nil && offset > 0 && offset < MaxDetailWindowBytes && strconv.Itoa(offset) == after
}

func ValidLogCursor(cursor string) bool {
	_, _, ok := parseLogCursor(cursor)
	return ok
}

type readWindow struct {
	user    string
	query   Query
	result  Result
	expires int64
	detail  []byte
	digest  [32]byte
}

func (w readWindow) size() int { return len(w.result.Stdout) + len(w.result.Stderr) + len(w.detail) }
func (w readWindow) clear()    { clear(w.result.Stdout); clear(w.result.Stderr); clear(w.detail) }

// ReadPages holds only redacted log/detail windows in the existing owner process.
// A cursor is a random handle, never content/matcher state or authorization.
// Current user/Task/native permission is checked by the runtime on every page.
// Time/nonce are caller inputs; this core never samples external state.
type ReadPages struct {
	mu      sync.Mutex
	windows map[string]readWindow
	bytes   int
}

func (*ReadPages) MarshalJSON() ([]byte, error) { return nil, ErrQuery }
func (*ReadPages) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private redacted log windows]")
}

func (p *ReadPages) expire(at int64) {
	for id, window := range p.windows {
		if at >= window.expires {
			p.bytes -= window.size()
			window.clear()
			delete(p.windows, id)
		}
	}
}

func (p *ReadPages) Open(user string, target Target, query Query, result Result, nonce [32]byte, at int64) (Result, error) {
	if !validReadWindowScope(user, nonce, at) {
		return Result{}, ErrQuery
	}
	if query.Validate() != nil || query.Kind != "logs" || query.Cursor != "" || !target.Valid() || !result.Target.Matches(target) || result.Target.NativeID == "" || result.Schema != 1 || result.Kind != "logs" || result.Truncated || result.NextCursor != "" || result.LogCode != "" || result.DetailCode != "" || result.DetailPart != nil || result.Detail != nil || result.Stats != nil || result.Processes != nil || result.Titles != nil || result.ObservedAt.IsZero() || result.TTY && len(result.Stderr) != 0 || !ValidLogDriver(result.LogDriver) {
		return Result{}, ErrQuery
	}
	total := len(result.Stdout) + len(result.Stderr)
	if total > MaxLogWindowBytes {
		return Result{}, ErrLogWindowLimit
	}
	if total <= query.MaxBytes {
		return result, nil
	}
	result.Stdout = bytes.Clone(result.Stdout)
	result.Stderr = bytes.Clone(result.Stderr)
	window := readWindow{user: user, query: query, result: result, expires: at + LogWindowSeconds}
	return p.keep(window, nonce, at)
}

func (p *ReadPages) OpenDetail(user string, target Target, query Query, result Result, nonce [32]byte, at int64) (Result, error) {
	if !validReadWindowScope(user, nonce, at) {
		return Result{}, ErrQuery
	}
	if query.Cursor != "" || result.ValidateDetailWindow(query, target) != nil {
		return Result{}, ErrQuery
	}
	raw, err := json.Marshal(result.Detail)
	if err != nil || len(raw) > MaxDetailWindowBytes {
		return Result{}, ErrLogWindowLimit
	}
	if len(raw) <= query.MaxBytes {
		return result, nil
	}
	result.Detail = nil
	window := readWindow{user: user, query: query, result: result, expires: at + LogWindowSeconds, detail: raw, digest: sha256.Sum256(raw)}
	return p.keep(window, nonce, at)
}

func (p *ReadPages) keep(window readWindow, nonce [32]byte, at int64) (Result, error) {
	if window.user == "" || nonce == ([32]byte{}) || at <= 0 || at > int64(^uint64(0)>>1)-LogWindowSeconds {
		window.clear()
		return Result{}, ErrQuery
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expire(at)
	if len(p.windows) >= maxLogWindows || window.size() > maxLogPageBytes-p.bytes {
		window.clear()
		return Result{}, ErrLogCursorCapacity
	}
	if p.windows == nil {
		p.windows = map[string]readWindow{}
	}
	id := hex.EncodeToString(nonce[:])
	if _, exists := p.windows[id]; exists {
		window.clear()
		return Result{}, ErrQuery
	}
	p.windows[id] = window
	p.bytes += window.size()
	return window.page(id, 0), nil
}

func (p *ReadPages) Next(user string, target Target, query Query, at int64) (Result, error) {
	id, offset, ok := parseLogCursor(query.Cursor)
	if !ok || query.Validate() != nil || query.Kind != "logs" && query.Kind != "inspect" || !target.Valid() || at <= 0 {
		return Result{}, ErrQuery
	}
	query.Cursor = ""
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expire(at)
	window, found := p.windows[id]
	if !found || window.user != user || window.query != query || !window.result.Target.Matches(target) || offset%query.MaxBytes != 0 || offset >= window.size() {
		return Result{}, ErrLogCursorExpired
	}
	return window.page(id, offset), nil
}

func (w readWindow) page(id string, offset int) Result {
	out := w.result
	if w.detail != nil {
		end := min(offset+w.query.MaxBytes, len(w.detail))
		out.DetailPart = &DetailPart{Snapshot: id, Offset: offset, Length: len(w.detail), Digest: w.digest, Data: bytes.Clone(w.detail[offset:end])}
		out.Truncated = end < len(w.detail)
		if out.Truncated {
			out.NextCursor = id + ":" + strconv.Itoa(end)
		}
		return out
	}
	end := min(offset+w.query.MaxBytes, len(w.result.Stdout)+len(w.result.Stderr))
	out.Stdout = nil
	out.Stderr = nil
	if offset < len(w.result.Stdout) {
		out.Stdout = bytes.Clone(w.result.Stdout[offset:min(end, len(w.result.Stdout))])
	}
	if end > len(w.result.Stdout) {
		out.Stderr = bytes.Clone(w.result.Stderr[max(0, offset-len(w.result.Stdout)) : end-len(w.result.Stdout)])
	}
	out.Truncated = end < len(w.result.Stdout)+len(w.result.Stderr)
	if out.Truncated {
		out.NextCursor = id + ":" + strconv.Itoa(end)
	}
	return out
}

func (p *ReadPages) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, window := range p.windows {
		window.clear()
	}
	p.windows = nil
	p.bytes = 0
}
