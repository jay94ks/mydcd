// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

// A small MCP client (Streamable HTTP, protocol 2025-06-18): initialize,
// tools/list and tools/call over POST, answers as JSON or an SSE stream.
// It goes through the webhook client: https, public addresses only, no
// redirects. Answer bodies are never logged or stored.

const (
	mcpProtocol     = "2025-06-18"
	mcpTimeout      = 15 * time.Second
	mcpMaxBody      = 1 << 20
	mcpMaxPages     = 10
	mcpMaxTools     = 200
	mcpToolDescMax  = 2000
	mcpToolNameMax  = 64
	mcpSessionIDMax = 256
)

type mcpConn struct {
	hc      *http.Client
	url     string
	token   string
	session string
	proto   string
	nextID  int
}

// mcpError is a failure shown to the administrator as is ("401
// Unauthorized", "tools/list: …"); never the answer body.
type mcpError struct{ msg string }

func (e *mcpError) Error() string { return e.msg }

func mcpErrorf(format string, a ...any) error { return &mcpError{fmt.Sprintf(format, a...)} }

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpListedTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations struct {
		Title        string `json:"title"`
		ReadOnlyHint bool   `json:"readOnlyHint"`
	} `json:"annotations"`
}

// mcpDial opens a session: initialize, then notifications/initialized.
func (s *Server) mcpDial(ctx context.Context, rawURL, token string) (*mcpConn, *mcpServerInfo, error) {
	if msg := s.checkWebhookURL(rawURL); msg != "" {
		return nil, nil, mcpErrorf("%s", msg)
	}
	c := &mcpConn{hc: s.webhookClient(mcpTimeout), url: rawURL, token: token}
	var init struct {
		ProtocolVersion string        `json:"protocolVersion"`
		ServerInfo      mcpServerInfo `json:"serverInfo"`
	}
	if err := c.call(ctx, "initialize", map[string]any{"protocolVersion": mcpProtocol, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "sfc-web", "version": "1"}}, &init); err != nil {
		return nil, nil, err
	}
	switch init.ProtocolVersion {
	case "2025-06-18", "2025-03-26":
		c.proto = init.ProtocolVersion
	default:
		return nil, nil, mcpErrorf("initialize: protocol version %q is not supported", oneLine(init.ProtocolVersion, 32))
	}
	if err := c.notify(ctx, "notifications/initialized"); err != nil {
		return nil, nil, err
	}
	info := &mcpServerInfo{Name: oneLine(init.ServerInfo.Name, 100), Version: oneLine(init.ServerInfo.Version, 50)}
	return c, info, nil
}

// close ends the session (best effort).
func (c *mcpConn) close() {
	if c.session == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url, nil)
	if err != nil {
		return
	}
	c.headers(req)
	if res, err := c.hc.Do(req); err == nil {
		res.Body.Close()
	}
	c.hc.CloseIdleConnections()
}

func (c *mcpConn) headers(req *http.Request) {
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "sfc-web")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.proto != "" {
		req.Header.Set("MCP-Protocol-Version", c.proto)
	}
}

func (c *mcpConn) post(ctx context.Context, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, mcpErrorf("url: %v", err)
	}
	c.headers(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, mcpErrorf("timeout")
		}
		if strings.Contains(err.Error(), "address not allowed") {
			return nil, mcpErrorf("url: private addresses are not allowed")
		}
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) {
			return nil, mcpErrorf("connect: %v", ue.Unwrap())
		}
		return nil, mcpErrorf("connect: %v", err)
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		res.Body.Close()
		return nil, mcpErrorf("%d %s (redirects are not followed)", res.StatusCode, http.StatusText(res.StatusCode))
	}
	if res.StatusCode >= 400 {
		res.Body.Close()
		return nil, mcpErrorf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	return res, nil
}

func (c *mcpConn) notify(ctx context.Context, method string) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	res, err := c.post(ctx, body)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, mcpMaxBody))
	res.Body.Close()
	return nil
}

// call sends one request and decodes the matching answer's result.
func (c *mcpConn) call(ctx context.Context, method string, params any, out any) error {
	c.nextID++
	id := fmt.Sprint(c.nextID)
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method, "params": params})
	if err != nil {
		return err
	}
	res, err := c.post(ctx, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if sid := res.Header.Get("Mcp-Session-Id"); sid != "" && c.session == "" {
		if len(sid) > mcpSessionIDMax || strings.ContainsFunc(sid, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
			return mcpErrorf("%s: bad Mcp-Session-Id", method)
		}
		c.session = sid
	}
	ct, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	var msg *rpcMessage
	switch ct {
	case "application/json":
		raw, err := io.ReadAll(io.LimitReader(res.Body, mcpMaxBody+1))
		if err != nil {
			return mcpErrorf("%s: read: %v", method, err)
		}
		if len(raw) > mcpMaxBody {
			return mcpErrorf("%s: answer over 1 MiB", method)
		}
		var m rpcMessage
		if json.Unmarshal(raw, &m) != nil {
			return mcpErrorf("%s: not a JSON-RPC answer", method)
		}
		if string(m.ID) == id {
			msg = &m
		}
	case "text/event-stream":
		if msg, err = sseAnswer(res.Body, id); err != nil {
			return mcpErrorf("%s: %v", method, err)
		}
	default:
		return mcpErrorf("%s: unexpected content type %q", method, oneLine(ct, 64))
	}
	if msg == nil {
		return mcpErrorf("%s: no answer", method)
	}
	if msg.Error != nil {
		return mcpErrorf("%s: error %d: %s", method, msg.Error.Code, oneLine(msg.Error.Message, 200))
	}
	if out != nil && json.Unmarshal(msg.Result, out) != nil {
		return mcpErrorf("%s: malformed result", method)
	}
	return nil
}

// sseAnswer reads SSE events until the answer with id (requests and
// notifications from the server in between are skipped).
func sseAnswer(r io.Reader, id string) (*rpcMessage, error) {
	sc := bufio.NewScanner(io.LimitReader(r, mcpMaxBody+1))
	sc.Buffer(make([]byte, 64<<10), mcpMaxBody)
	var data strings.Builder
	total := 0
	flush := func() *rpcMessage {
		defer data.Reset()
		if data.Len() == 0 {
			return nil
		}
		var m rpcMessage
		if json.Unmarshal([]byte(data.String()), &m) != nil || string(m.ID) != id || m.Method != "" {
			return nil
		}
		return &m
	}
	for sc.Scan() {
		line := sc.Text()
		total += len(line) + 1
		if total > mcpMaxBody {
			return nil, errors.New("answer over 1 MiB")
		}
		switch {
		case line == "":
			if m := flush(); m != nil {
				return m, nil
			}
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read: %v", err)
	}
	if m := flush(); m != nil {
		return m, nil
	}
	return nil, errors.New("no answer")
}

// listTools pages through tools/list.
func (c *mcpConn) listTools(ctx context.Context) ([]mcpListedTool, error) {
	var out []mcpListedTool
	cursor := ""
	for range mcpMaxPages {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var page struct {
			Tools      []mcpListedTool `json:"tools"`
			NextCursor string          `json:"nextCursor"`
		}
		if err := c.call(ctx, "tools/list", params, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Tools...)
		if len(out) > mcpMaxTools {
			return nil, mcpErrorf("tools/list: more than %d tools", mcpMaxTools)
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
	return nil, mcpErrorf("tools/list: more than %d pages", mcpMaxPages)
}

// callTool runs tools/call; text is the text content joined (other
// content kinds are named only), isError the tool's own failure flag.
func (c *mcpConn) callTool(ctx context.Context, name string, args map[string]any) (text string, isError bool, err error) {
	if args == nil {
		args = map[string]any{}
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		IsError           bool            `json:"isError"`
	}
	if err := c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args}, &res); err != nil {
		return "", false, err
	}
	var parts []string
	for _, x := range res.Content {
		if x.Type == "text" {
			parts = append(parts, x.Text)
		} else {
			parts = append(parts, "["+oneLine(x.Type, 32)+" content]")
		}
	}
	if len(parts) == 0 && len(res.StructuredContent) > 0 {
		parts = append(parts, string(res.StructuredContent))
	}
	return strings.Join(parts, "\n"), res.IsError, nil
}
