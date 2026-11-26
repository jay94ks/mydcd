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
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/web/ai"
)

// The coordinator's tool catalog (W2.2). Every tool is one screen API
// route, so the screens and the coordinator share one definition and one
// code path: a read tool is a GET run on the person's own session, a
// change tool becomes a proposal whose approval sends that route's request
// on the person's session (signed with their key, like a click). The
// catalog is not filtered per user (the cache prefix stays shared); mydcd
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
	// change tools
	Title        string // card title; {param} is replaced
	Action       string // mydcd action shown on the card
	Target       string // "node/{node}"
	Impact       string // low / medium / high (rule-based)
	Revert       string
	Irreversible bool
	Confirm      string // the argument the person types again (irreversible)
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

// aiCatalog is sorted by name once (the request prefix must not move).
var aiCatalog = func() []aiToolDef {
	afterQ := map[string]any{"after": str("page cursor from the previous page's next")}
	tenantQ := map[string]any{"tenant": str("workspace (tenant) ID to narrow to")}
	sel := map[string]any{"service": str("service name"), "instance": str("instance (replica) name")}
	defs := []aiToolDef{
		// core
		{Name: "ops_list", Desc: "List the person's recent operations (changes sent from the web) with state.", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/ops"},
		{Name: "ops_get", Desc: "Read one operation's state and result by op ID (after a proposal was approved).", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/ops/{id}"},
		{Name: "tenants_list", Desc: "List the workspaces (tenants) the person can see.", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/tenants"},
		{Name: "dashboard_get", Desc: "Cluster dashboard summary: servers, apps, alerts.", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/dashboard"},
		{Name: "incidents_list", Desc: "List incidents (detected faults) the person can see, newest first, with the decision on each temporary action.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/incidents",
			Props: map[string]any{"scope": str("app or cluster"), "decision": str("pending, auto, approved, rejected, expired, none"), "tenant": str("workspace"), "app": str("app name")}},
		{Name: "incidents_get", Desc: "Read one incident: signals, timeline, candidates, assessment and any pending approval.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/incidents/{id}"},

		// cluster and servers
		{Name: "nodes_list", Desc: "List cluster servers (nodes) with role, state, cordon and revision.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes", Props: afterQ},
		{Name: "nodes_summary", Desc: "Per-server CPU, memory and disk usage summary.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/summary", Props: tenantQ},
		{Name: "node_tasks", Desc: "Containers (tasks) running on one server.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/tasks", Props: map[string]any{"tenant": str("workspace ID to narrow to"), "after": str("page cursor")}},
		{Name: "node_storage", Desc: "Storage roots of one server and their space.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/storage", Props: afterQ},
		{Name: "node_disks", Desc: "Disks of one server (size, used, mount).", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/disks"},
		{Name: "node_image_prune_plan", Desc: "Plan which unused images on a server can be removed and the space freed. Its plan value goes to node_image_prune.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/image-prune-plan"},
		{Name: "node_drain_plan", Desc: "Plan moving every task off a server: what moves where and what is blocked. Its plan and operation values go to node_drain.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/drain-plan"},
		{Name: "node_remove_plan", Desc: "What removing a server from the cluster would need and block.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/remove-plan"},
		{Name: "cluster_raft", Desc: "Control plane (Raft) status: leader, voters, health.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/raft"},
		{Name: "cluster_mesh", Desc: "Server-to-server network (mesh) links and their state.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/mesh"},
		{Name: "events_list", Desc: "Recent cluster events, newest first.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/events",
			Props: map[string]any{"tenant": str("workspace ID to narrow to"), "since": str("event cursor to read after"), "limit": integer("at most this many (default 50)")}},

		// workspace resources
		{Name: "apps_list", Desc: "Apps in a workspace with deployment state and health.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps", Props: afterQ},
		{Name: "tasks_list", Desc: "All containers (tasks) of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/tasks", Props: afterQ},
		{Name: "resources_list", Desc: "Shared resources of a workspace (networks, volumes, vault, registries…).", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/resources", Props: afterQ},
		{Name: "networks_list", Desc: "Networks of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/networks", Props: afterQ},
		{Name: "volumes_list", Desc: "Data stores (volumes) of a workspace with size and placement.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/volumes", Props: afterQ},
		{Name: "volume_get", Desc: "One data store (volume) with its backups and users.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/volumes/{name}"},
		{Name: "volume_backups_list", Desc: "Backups of a workspace's data stores.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/volume-backups", Props: afterQ},
		{Name: "vault_list", Desc: "Secret vault entries of a workspace: paths, key names and access. Never values.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/vault", Props: afterQ},
		{Name: "lifecycles_list", Desc: "Lifecycle scripts of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/lifecycles", Props: afterQ},
		{Name: "routes_list", Desc: "External access routes of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/routes"},
		{Name: "registries_list", Desc: "Image registries of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/registries"},
		{Name: "builds_list", Desc: "Image builds of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/builds"},
		{Name: "standalone_list", Desc: "Single containers (standalone) of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/standalone"},

		// one app
		{Name: "app_tasks", Desc: "Containers (tasks) of one app.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/tasks", Props: afterQ},
		{Name: "app_operation", Desc: "One app operation's progress and result.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/operations/{id}"},
		{Name: "app_source", Desc: "The running app.yaml of an app (secret-like values masked).", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/source", Props: map[string]any{"version": integer("app version (default: current)")}},
		{Name: "app_revisions", Desc: "Version history of an app.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/revisions", Props: afterQ},
		{Name: "app_cd", Desc: "Automatic deployment (CD) state of an app: candidate, pause, last sync.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/cd"},
		{Name: "app_cd_history", Desc: "Automatic deployment history of an app.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/cd/history", Props: afterQ},
		{Name: "app_relocation_check", Desc: "Whether an app's tasks can move to other servers.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/relocation-check"},
		{Name: "app_logs_clear_plan", Desc: "Plan clearing a task's log files: size and target. Its target goes to app_logs_clear.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/logs-clear/plan", Props: sel, Required: []string{"service"}},
		{Name: "task_detail", Desc: "One task's detail: state, restarts, last exit code, placement.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/task", Props: sel, Required: []string{"service"}},
		{Name: "task_history", Desc: "One task's recent state changes and exits.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/task/history", Props: sel, Required: []string{"service"}},
		{Name: "task_stats", Desc: "One task's CPU and memory samples.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/task/stats", Props: sel, Required: []string{"service"}},

		// changes (proposals)
		{Name: "node_cordon", Desc: "Stop new placements on a server (running tasks stay).", Kind: aiKindChange, Method: "POST", Path: "/api/v1/nodes/{node}/cordon",
			Props: map[string]any{"reason": str("why, shown with the operation")}, Title: "{node} 서버에 새 배치 막기", Action: "cordon-node", Target: "node/{node}",
			Impact: "low", Revert: "node_uncordon으로 다시 배치를 허용해요."},
		{Name: "node_uncordon", Desc: "Allow new placements on a cordoned server again.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/nodes/{node}/uncordon",
			Title: "{node} 서버에 배치 다시 허용", Action: "uncordon-node", Target: "node/{node}", Impact: "low", Revert: "node_cordon으로 다시 막을 수 있어요."},
		{Name: "node_image_prune", Desc: "Remove a server's unused images (from node_image_prune_plan).", Kind: aiKindChange, Method: "POST", Path: "/api/v1/nodes/{node}/image-prune",
			Props: map[string]any{"plan": str("plan value from node_image_prune_plan")}, Required: []string{"plan"},
			Title: "{node} 서버의 쓰지 않는 이미지 정리", Action: "prune-node-images", Target: "node/{node}", Impact: "low", Revert: "지운 이미지는 필요할 때 저장소에서 다시 받아요."},
		{Name: "node_drain", Desc: "Move every task off a server (from node_drain_plan).", Kind: aiKindChange, Method: "POST", Path: "/api/v1/nodes/{node}/drain",
			Props: map[string]any{"plan": str("plan value from node_drain_plan"), "operation": str("operation value from node_drain_plan"),
				"leaveBlocked": boolean("leave tasks that cannot move")}, Required: []string{"plan", "operation"},
			Title: "{node} 서버의 작업 모두 옮기기", Action: "drain-node", Target: "node/{node}", Impact: "high", Revert: "옮긴 작업은 자동으로 돌아오지 않아요. 필요하면 다시 배치해요."},
		{Name: "task_restart", Desc: "Restart one task of an app.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/task/restart",
			Props: sel, Required: []string{"service", "instance"},
			Title: "{app}의 {service} 작업 다시 시작", Action: "restart-task", Target: "app/{app}", Impact: "medium", Revert: "다시 시작은 되돌릴 수 없지만 상태는 그대로예요."},
		{Name: "app_cd_sync", Desc: "Deploy an app's automatic deployment candidate now.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/cd/sync",
			Title: "{app} 자동 배포 후보 지금 배포", Action: "sync-app", Target: "app/{app}", Impact: "medium", Revert: "이전 버전으로 되돌리기(recover)로 돌아가요."},
		{Name: "app_cd_pause", Desc: "Pause an app's automatic deployment.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/cd/pause",
			Title: "{app} 자동 배포 멈추기", Action: "pause-app-cd", Target: "app/{app}", Impact: "low", Revert: "app_cd_resume으로 다시 켜요."},
		{Name: "app_cd_resume", Desc: "Resume an app's paused automatic deployment.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/cd/resume",
			Title: "{app} 자동 배포 다시 켜기", Action: "resume-app-cd", Target: "app/{app}", Impact: "medium", Revert: "app_cd_pause로 다시 멈춰요."},
		{Name: "app_logs_clear", Desc: "Clear one task's log files (from app_logs_clear_plan). The logs are gone for good.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/logs-clear",
			Props: map[string]any{"service": str("service name"), "instance": str("instance name"), "target": str("target value from app_logs_clear_plan")}, Required: []string{"service", "target"},
			Title: "{app}의 {service} 로그 지우기", Action: "clear-app-logs", Target: "app/{app}", Impact: "medium", Revert: "지운 로그는 되돌릴 수 없어요.", Irreversible: true, Confirm: "app"},
		{Name: "volume_backup", Desc: "Start a backup of one data store (volume).", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/volumes/{name}/backups",
			Props: map[string]any{"app": str("app that owns the data store, if any")},
			Title: "{name} 데이터 저장소 백업", Action: "begin-volume-backup", Target: "volume/{name}", Impact: "low", Revert: "만든 백업은 지울 수 있어요."},
	}
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

var pathParamDesc = map[string]string{
	"t": "workspace (tenant) ID", "app": "app name", "node": "server (node) name", "name": "resource name", "id": "ID",
}

// schema is the tool's JSON Schema (fixed bytes: maps marshal sorted).
func (d aiToolDef) schema() map[string]any {
	props := map[string]any{}
	req := append([]string{}, d.pathParams()...)
	for _, p := range d.pathParams() {
		props[p] = str(pathParamDesc[p])
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
