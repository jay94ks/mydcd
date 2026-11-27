// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/web/ai"
)

// The coordinator's tool catalog (W2.2). Every tool is one screen API
// route, so the screens and the coordinator share one definition and one
// code path: a read tool is a GET run on the person's own session, a
// change tool becomes a proposal whose approval sends that route's request
// on the person's session (signed with their key, like a click). The
// catalog is not filtered per user (the cache prefix stays shared); sfcd
// judges permission when a tool runs.

// aiToolDef is one catalog entry. Path is the route pattern; its {params}
// are required string arguments. Props are the other arguments: query
// parameters of a read, body fields of a change.
type aiToolDef struct {
	Name     string
	Desc     string
	Kind     string // read / change
	Core     bool   // loaded up front (Claude); the rest are searched
	Method   string
	Path     string
	Props    map[string]any
	Required []string
	// change tools; the grade and undo come from webActions[Action]
	Title  string // card title; {param} is replaced
	Action string // sfcd action shown on the card
	Target string // "node/{node}"
}

const (
	aiKindRead   = "read"
	aiKindChange = "change"
)

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// Arguments several tools share.
var (
	afterQ  = map[string]any{"after": str("page cursor from the previous page's next")}
	tenantQ = map[string]any{"tenant": str("workspace (tenant) ID to narrow to")}
	sel     = map[string]any{"service": str("service name"), "instance": str("instance (replica) name")}
)

// aiCatalog is sorted by name once (the request prefix must not move).
// aiCatalog is every tool, sorted by name once (the request prefix must
// not move). A new area file adds its list here.
var aiCatalog = func() []aiToolDef {
	defs := slices.Concat(aiToolsCore, aiToolsCluster, aiToolsWorkspace, aiToolsApp)
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return defs
}()

var pathParamRE = regexp.MustCompile(`\{([a-z]+)\}`)

func (d aiToolDef) pathParams() []string {
	var out []string
	for _, m := range pathParamRE.FindAllStringSubmatch(d.Path, -1) {
		out = append(out, m[1])
	}
	return out
}

// aiArgInfo is what the tools say about one argument name: the schema
// description of a path value, and the card label of an argument a change
// tool takes (TestAIArgInfo checks both are there).
type aiArgInfo struct {
	Label    string
	PathDesc string
}

var aiArgInfos = map[string]aiArgInfo{
	"t":        {"작업 공간", "workspace (tenant) ID"},
	"app":      {"앱", "app name"},
	"node":     {"서버", "server (node) name"},
	"name":     {"이름", "resource name"},
	"id":       {"ID", "ID"},
	"service":  {"서비스", ""},
	"instance": {"인스턴스", ""},
	"plan":     {"계획", ""},
	"reason":   {"사유", ""},
	"target":   {"대상", ""},
}

// schema is the tool's JSON Schema (fixed bytes: maps marshal sorted).
func (d aiToolDef) schema() map[string]any {
	props := map[string]any{}
	req := append([]string{}, d.pathParams()...)
	for _, p := range d.pathParams() {
		props[p] = str(aiArgInfos[p].PathDesc)
	}
	for k, v := range d.Props {
		props[k] = v
	}
	req = append(req, d.Required...)
	sort.Strings(req)
	return map[string]any{"type": "object", "properties": props, "required": req, "additionalProperties": false}
}

// aiTools is the catalog as the ai package takes it.
var aiTools = func() []ai.Tool {
	out := make([]ai.Tool, 0, len(aiCatalog))
	for _, d := range aiCatalog {
		desc := d.Desc
		if d.Kind == aiKindChange {
			desc += " Creates a proposal the person approves; nothing changes before that."
		}
		out = append(out, ai.Tool{Name: d.Name, Description: desc, Schema: d.schema(), Core: d.Core})
	}
	return out
}()

func aiToolByName(name string) (aiToolDef, bool) {
	i := sort.Search(len(aiCatalog), func(i int) bool { return aiCatalog[i].Name >= name })
	if i < len(aiCatalog) && aiCatalog[i].Name == name {
		return aiCatalog[i], true
	}
	return aiToolDef{}, false
}

var safeParamRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// aiArgs is a checked call: path filled, the rest as query or body.
type aiArgs struct {
	raw    map[string]any
	path   string
	query  url.Values
	body   map[string]any
	tenant string
}

// check validates the input against the tool's schema (the model's input
// is never trusted) and builds the request.
func (d aiToolDef) check(input json.RawMessage) (*aiArgs, error) {
	var in map[string]any
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&in); err != nil || in == nil {
		return nil, fmt.Errorf("input must be a JSON object")
	}
	sc := d.schema()
	props := sc["properties"].(map[string]any)
	for k := range in {
		if _, ok := props[k]; !ok {
			return nil, fmt.Errorf("unknown argument %q", k)
		}
	}
	for _, k := range sc["required"].([]string) {
		if v, ok := in[k]; !ok || v == "" {
			return nil, fmt.Errorf("argument %q is required", k)
		}
	}
	a := &aiArgs{raw: in, query: url.Values{}, body: map[string]any{}}
	for k, v := range in {
		typ := props[k].(map[string]any)["type"]
		switch typ {
		case "string":
			if _, ok := v.(string); !ok {
				return nil, fmt.Errorf("argument %q must be a string", k)
			}
		case "integer":
			n, ok := v.(json.Number)
			if _, err := n.Int64(); !ok || err != nil {
				return nil, fmt.Errorf("argument %q must be an integer", k)
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return nil, fmt.Errorf("argument %q must be true or false", k)
			}
		}
	}
	a.path = pathParamRE.ReplaceAllStringFunc(d.Path, func(m string) string {
		v, _ := in[m[1:len(m)-1]].(string)
		return v
	})
	for _, p := range d.pathParams() {
		v, _ := in[p].(string)
		if !safeParamRE.MatchString(v) {
			return nil, fmt.Errorf("argument %q is not a valid name", p)
		}
		if p == "t" {
			a.tenant = v
		}
	}
	if tn, ok := in["tenant"].(string); ok && a.tenant == "" {
		a.tenant = tn
	}
	for k, v := range in {
		if strings.Contains(d.Path, "{"+k+"}") {
			continue
		}
		if d.Kind == aiKindRead {
			a.query.Set(k, fmt.Sprint(v))
		} else {
			a.body[k] = v
		}
	}
	return a, nil
}

// fill replaces {param} in a card template.
func (a *aiArgs) fill(tmpl string) string {
	return pathParamRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		v, _ := a.raw[m[1:len(m)-1]].(string)
		return v
	})
}

type ctxSession struct{}

// dispatch runs one API route on ws's session, in process (no cookie, no
// CSRF check: the call does not come from a browser). It returns the
// status and body.
func (s *Server) dispatch(ctx context.Context, ws *webSession, method, path string, query url.Values, body []byte) (int, []byte) {
	return s.dispatchWith(ctx, ws, method, path, query, body, nil)
}

// dispatchWith is dispatch with extra request headers.
func (s *Server) dispatchWith(ctx context.Context, ws *webSession, method, path string, query url.Values, body []byte, hdr map[string]string) (int, []byte) {
	u := path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequestWithContext(context.WithValue(ctx, ctxSession{}, ws), method, u, rd)
	if err != nil {
		return http.StatusBadRequest, []byte(`{"error":{"code":"bad-request"}}`)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, r)
	return rec.Code, rec.Body.Bytes()
}

// Masking what goes to the vendors and into the conversation record.

var (
	secretKeyRE = regexp.MustCompile(`(?i)(password|passwd|passphrase|secret|token|credential|private.?key|api.?key|^key$)`)
	// app.yaml / env lines whose variable name looks secret.
	secretEnvRE = regexp.MustCompile(`(?m)^(\s*-?\s*"?)([A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY|PASSWD|CREDENTIAL)[A-Za-z0-9_]*)("?\s*[:=]\s*)(\S.*)$`)
)

const (
	aiMasked       = "«가림»"
	aiArgMax       = 200
	aiResultMax    = 16 << 10
	aiExcludedText = "이 작업 공간의 데이터는 외부 AI로 보내지 않게 설정되어 있어요."
)

// maskArgs is the record and display form of a call's arguments.
func maskArgs(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		var s string
		switch x := v.(type) {
		case string:
			s = x
		default:
			b, _ := json.Marshal(x)
			s = string(b)
		}
		switch {
		case secretKeyRE.MatchString(k) || secretEnvRE.MatchString(s):
			s = aiMasked
		case utf8.RuneCountInString(s) > aiArgMax:
			s = string([]rune(s)[:aiArgMax]) + "…"
		}
		out[k] = s
	}
	return out
}

// maskResult masks a read result before it goes to the model: values
// under secret-like keys, secret-like env values in text (and the same
// values anywhere else), then caps the size.
func maskResult(raw []byte, maskEnv bool, ex *aiExcluder) string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return capText(ex.text(string(raw)))
	}
	seen := map[string]bool{}
	var walk func(x any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if s, ok := val.(string); ok && secretKeyRE.MatchString(k) && s != "" {
					if len(s) >= 4 {
						seen[s] = true
					}
					t[k] = aiMasked
					continue
				}
				t[k] = walk(val)
			}
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		case string:
			if maskEnv {
				return secretEnvRE.ReplaceAllStringFunc(t, func(line string) string {
					m := secretEnvRE.FindStringSubmatch(line)
					val := strings.Trim(strings.TrimSpace(m[4]), `"'`)
					if len(val) >= 4 {
						seen[val] = true
					}
					return m[1] + m[2] + m[3] + "«가림: " + m[2] + "»"
				})
			}
		}
		return x
	}
	// A single object of an excluded workspace (one incident, one op) goes
	// whole, like a read of that workspace.
	if m, ok := v.(map[string]any); ok && ex != nil && ex.rowExcluded(m) {
		return aiExcludedText
	}
	v = ex.drop(walk(v))
	out, _ := json.Marshal(v)
	text := string(out)
	for s := range seen {
		text = strings.ReplaceAll(text, s, aiMasked)
	}
	return capText(ex.text(text))
}

func capText(s string) string {
	if len(s) <= aiResultMax {
		return s
	}
	cut := aiResultMax
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n…(잘림: 결과가 길어 앞부분만 보냈어요. 범위를 좁혀 다시 읽으세요.)"
}

// aiExcluder keeps the workspaces in data.excludeTenants away from the
// vendors: rows that name one are dropped from read results, and the name
// is replaced anywhere else (results, the question, the turn context).
type aiExcluder struct {
	names map[string]bool
	re    *regexp.Regexp
}

const aiExcludedName = "«제외된 작업 공간»"

func newAIExcluder(names []string) *aiExcluder {
	e := &aiExcluder{names: map[string]bool{}}
	var alts []string
	for _, n := range names {
		if n != "" {
			e.names[n] = true
			alts = append(alts, regexp.QuoteMeta(n))
		}
	}
	if len(alts) > 0 {
		// The name as a word; - counts as a break, so resource names built
		// from it (payments-net) are hidden too.
		e.re = regexp.MustCompile(`(^|[^A-Za-z0-9_])(` + strings.Join(alts, "|") + `)($|[^A-Za-z0-9_])`)
	}
	return e
}

func (e *aiExcluder) has(name string) bool { return e != nil && e.names[name] }

// mentions: s names an excluded workspace somewhere.
func (e *aiExcluder) mentions(s string) bool {
	return e != nil && e.re != nil && e.re.MatchString(s)
}

func (e *aiExcluder) text(s string) string {
	if e == nil || e.re == nil {
		return s
	}
	// Twice: adjacent matches share a boundary character.
	for i := 0; i < 2; i++ {
		s = e.re.ReplaceAllString(s, "${1}"+aiExcludedName+"${3}")
	}
	return s
}

// drop removes list rows (objects) whose own string fields name an
// excluded workspace.
func (e *aiExcluder) drop(v any) any {
	if e == nil || len(e.names) == 0 {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = e.drop(x)
		}
	case []any:
		out := t[:0]
		for _, x := range t {
			if m, ok := x.(map[string]any); ok && e.rowExcluded(m) {
				continue
			}
			out = append(out, e.drop(x))
		}
		return out
	}
	return v
}

// rowExcluded: one of the row's own string fields is an excluded
// workspace (its tenant field, or the ID of a workspace row).
func (e *aiExcluder) rowExcluded(m map[string]any) bool {
	for _, x := range m {
		if s, ok := x.(string); ok && e.names[s] {
			return true
		}
	}
	return false
}
