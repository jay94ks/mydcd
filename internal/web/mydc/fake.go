// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/secrets"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// Fake is the in-memory adapter. It implements Client, keeps state across
// connections, follows the mydcd contract for permissions, CAS, original
// results and failures, and lets tests inject failures. It is safe for
// concurrent use.
type Fake struct {
	mu sync.Mutex
	w  *world

	clock       func() time.Time
	idleTimeout time.Duration
	pageSize    int

	quorum      bool
	version     *ServerVersion // REQ-48 (nil: FixtureServerVersion)
	issuer      bool
	failures    map[string][]*Error
	loseReplies map[string][]bool // method → applied?

	streamTick time.Duration
	streams    map[*fakeStream]bool
}

// NewFake builds a Fake from a fixture (use DefaultFixture()).
func NewFake(f Fixture) *Fake {
	return &Fake{
		w:           newWorld(f),
		clock:       time.Now,
		idleTimeout: 30 * time.Second,
		pageSize:    50,
		quorum:      true,
		issuer:      true,
		failures:    map[string][]*Error{},
		loseReplies: map[string][]bool{},
		streamTick:  2 * time.Second,
		streams:     map[*fakeStream]bool{},
	}
}

// SetClock replaces the time source (tests).
func (f *Fake) SetClock(now func() time.Time) { f.mu.Lock(); f.clock = now; f.mu.Unlock() }

// SetIdleTimeout changes the Unix idle limit (default 30 s, 0 disables).
// Reconnects reports how many times c dialed again after mydcd closed its
// idle connection (fake only, for tests).
func Reconnects(c Conn) int {
	fc, ok := c.(*fakeConn)
	if !ok {
		return 0
	}
	fc.f.mu.Lock()
	defer fc.f.mu.Unlock()
	return fc.reconnects
}

func (f *Fake) SetIdleTimeout(d time.Duration) { f.mu.Lock(); f.idleTimeout = d; f.mu.Unlock() }

// SetPageSize changes the page size of paginated methods (default 50).
func (f *Fake) SetPageSize(n int) { f.mu.Lock(); f.pageSize = max(1, n); f.mu.Unlock() }

// SetQuorum(false) makes every session method fail with CodeUnavailable.
// SetLedgerBusy makes rotate-ledger fail as mydcd does while work is in
// progress (storageQuiescent false).
func (f *Fake) SetLedgerBusy(busy bool) { f.mu.Lock(); f.w.ledgerBusy = busy; f.mu.Unlock() }

func (f *Fake) SetQuorum(ok bool) { f.mu.Lock(); f.quorum = ok; f.mu.Unlock() }

// SetSessionIssuer(false) makes logins fail with CodeNotSessionIssuer, as on
// a non-voter server.
func (f *Fake) SetSessionIssuer(ok bool) { f.mu.Lock(); f.issuer = ok; f.mu.Unlock() }

// FailNext makes the next call of a wire method (e.g. "apps", "submit") fail
// with the given code. Calls queue in order.
func (f *Fake) FailNext(method string, code Code) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[method] = append(f.failures[method], &Error{Code: code, Method: method, Detail: "injected"})
}

// LoseNextReply makes the next submit/resume reply get lost after the server
// decided: applied=true commits the change, false does not. The caller sees
// CodeUnknown either way.
func (f *Fake) LoseNextReply(method string, applied bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loseReplies[method] = append(f.loseReplies[method], applied)
}

// AddEvent appends an observation event and returns its cursor.
func (f *Fake) AddEvent(e FixtureEvent) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w.addEvent(e)
}

// TrimEvents drops events up to and including cursor (simulates retention).
func (f *Fake) TrimEvents(cursor string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.trimEvents(cursor)
}

// RootRevision is the current management root revision.
func (f *Fake) RootRevision() uint64 { f.mu.Lock(); defer f.mu.Unlock(); return f.w.root }

// Journal lists the RequestIDs of all accepted originals in commit order, and
// whether the fake actually modeled the action (false = recorded only).
func (f *Fake) Journal() []JournalEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]JournalEntry(nil), f.w.journal...)
}

type JournalEntry struct {
	RequestID, Action, User string
	Result                  Result
	Modeled                 bool
	Reason                  *OperationReason `json:",omitempty"` // REQ-9
}

func (f *Fake) now() time.Time { return f.clock() }

func (f *Fake) injected(method string) error {
	q := f.failures[method]
	if len(q) == 0 {
		return nil
	}
	f.failures[method] = q[1:]
	return q[0]
}

func (f *Fake) loseReply(method string) (lost, applied bool) {
	q := f.loseReplies[method]
	if len(q) == 0 {
		return false, false
	}
	f.loseReplies[method] = q[1:]
	return true, q[0]
}

// Dial opens a new unauthenticated connection.
func (f *Fake) Dial(ctx context.Context) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fail("dial", CodeTransport, err.Error())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return &fakeConn{f: f, last: f.now()}, nil
}

type fakeConn struct {
	f          *Fake
	closed     bool
	last       time.Time
	ticket     *Ticket
	key        ed25519.PrivateKey // session key for the pending ticket / session
	session    *Session
	reconnects int // R03: idle disconnections the Conn dialed again after
	// loginKey: the user key of the current key login (ApproveSession)
	loginKey [32]byte
}

// begin runs the common per-exchange checks with f.mu held.
func (c *fakeConn) begin(ctx context.Context, method string, needSession bool) error {
	if err := ctx.Err(); err != nil {
		return fail(method, CodeTransport, err.Error())
	}
	now := c.f.now()
	if !c.closed && c.f.idleTimeout > 0 && now.Sub(c.last) > c.f.idleTimeout {
		// mydcd closed the idle connection and the Conn dials again (R03).
		// The login Session is bound to the session key, not the
		// connection, so it survives; a pending ticket is bound to the old
		// connection's challenge and is lost.
		c.reconnects++
		c.ticket = nil
	}
	if c.closed {
		return fail(method, CodeClosed, "connection closed")
	}
	c.last = now
	if err := c.f.injected(method); err != nil {
		return err
	}
	if !needSession {
		return nil
	}
	if c.session == nil {
		return fail(method, CodeNotLoggedIn, "")
	}
	if now.Unix() >= c.session.ExpiresAt {
		return fail(method, CodeSessionExpired, "")
	}
	if c.f.w.revoked[c.session.User+"/"+c.session.ID] {
		return fail(method, CodeDenied, "session revoked")
	}
	u := c.f.w.users[c.session.User]
	if u == nil || !u.rec.Enabled {
		return fail(method, CodeDenied, "account disabled")
	}
	if !c.f.quorum {
		return fail(method, CodeUnavailable, "no quorum")
	}
	return nil
}

func (c *fakeConn) Close() error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) Session() (Session, bool) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.session == nil || c.closed {
		return Session{}, false
	}
	return *c.session, true
}

func random32() (b [32]byte) {
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return b
}

func keyHex(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

func pub32(k ed25519.PrivateKey) (p [32]byte) {
	copy(p[:], k.Public().(ed25519.PublicKey))
	return p
}

func (c *fakeConn) newTicket(u *fakeUser, cred Credential, userKey [32]byte) (Ticket, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ticket{}, err
	}
	w := c.f.w
	now := c.f.now().Unix()
	t := Ticket{
		Schema: 1, Cluster: w.cluster, User: u.rec.ID, Username: u.rec.Username,
		Credential: cred.ID, AccountRevision: u.rec.Revision,
		SessionKey: pub32(key), UserKey: userKey, Challenge: random32(), Nonce: random32(),
		Issuer: pub32(w.issuer), IssuedAt: now, Deadline: now + 300,
	}
	if cred.Method != MethodPrivateKey {
		t.AuthMethod = cred.Method
	}
	t.Signature = ed25519.Sign(w.issuer, TicketSigningBytes(t))
	c.ticket, c.key, c.session, c.loginKey = &t, key, nil, [32]byte{}
	return t, nil
}

func (c *fakeConn) CredentialChallenge(ctx context.Context, username string, method AuthMethod, credential string) (Ticket, error) {
	const m = "credential-challenge"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, false); err != nil {
		return Ticket{}, err
	}
	if !c.f.issuer {
		return Ticket{}, fail(m, CodeNotSessionIssuer, "")
	}
	if method != MethodPassword && method != MethodToken {
		return Ticket{}, fail(m, CodeInvalid, "method")
	}
	u := c.f.w.byName(username)
	if u == nil || !u.rec.Enabled || c.f.w.keyOnly(u.rec.ID) {
		return Ticket{}, fail(m, CodeDenied, "")
	}
	for _, cr := range u.rec.Credentials {
		if cr.Enabled && cr.Method == method && (credential == "" || cr.ID == credential) {
			return c.newTicket(u, cr, [32]byte{})
		}
	}
	return Ticket{}, fail(m, CodeDenied, "")
}

func (c *fakeConn) CredentialLogin(ctx context.Context, t Ticket, secret []byte) (Session, error) {
	const m = "credential-login"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, false); err != nil {
		return Session{}, err
	}
	if !c.f.issuer {
		return Session{}, fail(m, CodeNotSessionIssuer, "")
	}
	u, err := c.checkTicket(m, t)
	if err != nil {
		return Session{}, err
	}
	c.ticket = nil
	want := u.secret
	if t.AuthMethod == MethodToken && u.token != "" {
		want = u.token
	}
	if t.AuthMethod == "" || subtle.ConstantTimeCompare([]byte(want), secret) != 1 || want == "" {
		return Session{}, fail(m, CodeDenied, "")
	}
	if t.AuthMethod == MethodToken && u.token != "" {
		// one-time: the issued token credential is turned off on first use
		u.token = ""
		rec := cloneUser(u.rec)
		for i := range rec.Credentials {
			if rec.Credentials[i].ID == "initial-token" {
				rec.Credentials[i].Enabled = false
			}
		}
		u.rec = rec
	}
	return c.issue(u, t), nil
}

func (c *fakeConn) Challenge(ctx context.Context, username string, userKey [32]byte) (Ticket, error) {
	const m = "challenge"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, false); err != nil {
		return Ticket{}, err
	}
	if !c.f.issuer {
		return Ticket{}, fail(m, CodeNotSessionIssuer, "")
	}
	u := c.f.w.byName(username)
	if u == nil || !u.rec.Enabled {
		return Ticket{}, fail(m, CodeDenied, "")
	}
	for _, cr := range u.rec.Credentials {
		if cr.Enabled && cr.Method == MethodPrivateKey && cr.PublicKey == userKey {
			return c.newTicket(u, cr, userKey)
		}
	}
	return Ticket{}, fail(m, CodeDenied, "")
}

func (c *fakeConn) Login(ctx context.Context, t Ticket, p KeyProof) (Session, error) {
	const m = "login"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, false); err != nil {
		return Session{}, err
	}
	if !c.f.issuer {
		return Session{}, fail(m, CodeNotSessionIssuer, "")
	}
	u, err := c.checkTicket(m, t)
	if err != nil {
		return Session{}, err
	}
	c.ticket = nil
	want := NewKeyProof(t)
	got := p
	got.Signature = nil
	if t.AuthMethod != "" || got.Schema != want.Schema || got.Cluster != want.Cluster || got.User != want.User ||
		got.Username != want.Username || got.Credential != want.Credential || got.Challenge != want.Challenge ||
		got.SessionKey != want.SessionKey || got.Deadline != want.Deadline ||
		!ed25519.Verify(t.UserKey[:], KeyProofSigningBytes(p), p.Signature) {
		return Session{}, fail(m, CodeDenied, "")
	}
	for _, cr := range u.rec.Credentials {
		if cr.ID == t.Credential && cr.Enabled && cr.PublicKey == t.UserKey {
			s := c.issue(u, t)
			c.loginKey = t.UserKey
			return s, nil
		}
	}
	return Session{}, fail(m, CodeDenied, "")
}

func (c *fakeConn) ApproveSession(ctx context.Context, a SessionApproval) (Session, error) {
	const m = "approve-session"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, true); err != nil {
		return Session{}, err
	}
	if c.session.Approval != nil || c.loginKey != a.PublicKey {
		return Session{}, fail(m, CodeDenied, "")
	}
	s, err := access.AttachSessionApproval(*c.session, a)
	if err != nil {
		return Session{}, fail(m, CodeDenied, "")
	}
	for _, cr := range c.f.w.users[s.User].rec.Credentials {
		if cr.Enabled && cr.Method == MethodPrivateKey && cr.PublicKey == a.PublicKey {
			c.session = &s
			return s, nil
		}
	}
	return Session{}, fail(m, CodeDenied, "")
}

// checkTicket requires the exact ticket this connection was issued.
func (c *fakeConn) checkTicket(m string, t Ticket) (*fakeUser, error) {
	if c.ticket == nil || string(TicketSigningBytes(*c.ticket)) != string(TicketSigningBytes(t)) ||
		subtle.ConstantTimeCompare(c.ticket.Signature, t.Signature) != 1 {
		return nil, fail(m, CodeDenied, "ticket")
	}
	if c.f.now().Unix() > t.Deadline {
		c.ticket = nil
		return nil, fail(m, CodeExpired, "ticket")
	}
	u := c.f.w.users[t.User]
	if u == nil || !u.rec.Enabled || u.rec.Revision != t.AccountRevision {
		return nil, fail(m, CodeDenied, "")
	}
	return u, nil
}

func (c *fakeConn) issue(u *fakeUser, t Ticket) Session {
	w := c.f.w
	now := c.f.now().Unix()
	id := random32()
	s := Session{
		Schema: 1, ID: hex.EncodeToString(id[:12]), Cluster: w.cluster, User: u.rec.ID,
		Credential: t.Credential, AccountRevision: u.rec.Revision, Key: t.SessionKey,
		Issuer: pub32(w.issuer), IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 3600,
		Scopes: w.scopes(u.rec.ID),
	}
	s.Signature = ed25519.Sign(w.issuer, access.SessionBytes(s))
	c.session = &s
	return s
}

// --- world ---

type fakeUser struct {
	rec    User
	secret string
	token  string // REQ-27 one-time token (fake only)
}

type fakeApp struct {
	view      AppView
	sources   []AppSource
	ops       map[string]*AppOperation
	tasks     []Task
	overrides map[string]Task

	cdOverrides []cdOverride // CD runtime overrides (fake_cd.go)
	cd          *cdState     // REQ-46 Git documents and history (fake_cd_history.go)
}

type upload struct {
	view   AppUploadView
	user   string
	tenant string
	parts  map[int][]byte
}

type ledgerEntry struct {
	digest [32]byte
	result Result
}

type world struct {
	cluster [32]byte
	issuer  ed25519.PrivateKey
	root    uint64
	// keyRoots: root revision per control.CommandKey (fake_roots.go).
	keyRoots    map[string]uint64
	seedRoot    uint64
	strictRoots bool

	users       map[string]*fakeUser
	tenants     map[string]map[string]Role
	tenantRev   map[string]uint64
	tenantNodes map[string][]string
	revoked     map[string]bool
	nodeCLI     NodeCLIPolicy

	// REQ-17 external registry logins, REQ-19 builds.
	extSeed      []FixtureExternalRegistry
	loginResult  map[string]string
	ext          extRealState // real REQ-17 (fake_external_registries_real.go)
	mnt          maintState   // real REQ-18 jobs (fake_registry_maintenance.go)
	build        buildState
	tasksState   map[string]*taskState // REQ-20 per task
	logDrivers   map[string]string     // per task (default local)
	logClears    map[string]*logClear  // clear-app-logs by tenant/app/operation
	svc          *serviceCalls         // REQ-24
	probe        *cdProbeState         // REQ-56
	tunJobs      tunnelJobs            // RQ4 tunnel-reconnect jobs (real shape)
	shell        *shellState           // REQ-67 server shell
	nodeImages   map[string]map[string]fixtureNodeImage
	imageJobs    map[string]ImageCacheStatus   // prune-node-images jobs by operation
	volFiles     map[string]map[string]volFile // REQ-28 tenant/volume → path
	volGrants    []VolumeFileGrant
	volGrantMeta map[string]volGrantMeta // REQ-49 by grantKey
	volJobs      map[string]*volFileJob  // REQ-28 real, by control.VolumeFileID

	members     []FixtureMember
	summaries   []FixtureNodeSummary
	disks       []FixtureDisk
	links       []FixtureLink
	raft        FixtureRaft
	nodeStorage []FixtureStorageRoot
	// observeLimit: REQ-53 FixtureNodeSummary.ObserveLimitSeconds.
	observeLimit int64
	resources    []ResourceEntry
	volumes      []volumeRow
	backups      []VolumeBackupView
	restores     []VolumeRestoreView
	vault        []VaultView
	ledgerEpoch  uint64                     // ModuleEpoch (rotate-ledger)
	retiring     map[string]string          // tenant → retirement operation
	retired      map[string]bool            // tenant phase deleted
	ledgerBusy   bool                       // !storageQuiescent
	netRev       uint64                     // Networks.Revision (create-network Expected)
	netTargets   map[string]tenancy.Network // planned change targets by tenant/member
	routeOpen    map[string]bool            // tenant/network offered as route destination
	routes       []tenancy.Route            // cross-tenant routes (fake_routes.go)
	vaultRev     map[string]uint64          // tenant → Vault tree revision (vault-create Expected)
	vaultWrites  map[string]*fakeVaultWrite // realm/write ID

	lcPolicies  map[string][]checker.TenantPolicy // tenant → policy versions (fake_lifecycles.go)
	lcScripts   map[string]*lcScript              // tenant/name
	lcUses      map[string][]LifecycleUse         // tenant/name: fixture work pinning versions (build jobs)
	lcOverride  map[string][]LifecycleUse         // tenant/name: Fake.SetLifecycleUses
	lcStaged    map[[32]byte]string               // staged source text by digest
	lcUploads   map[string]*lcUpload              // REQ-39 real stage: node/upload hex
	lcNextDiags []checker.SourceDiagnostic        // Fake.FailNextLifecycleStage

	groupVerifiers map[string]identity.PasswordVerifier // realm/group password (fake_vault_approvals.go)
	approvals      map[string]secrets.Target            // realm/group/begin-app request ID
	approvalRows   map[string]*VaultApprovalRow         // approval ID → row (revoked rows kept)
	approvalRev    uint64                               // Vault.Approvals revision (vault-revoke-approval Expected)

	moves map[string]*fakeMove // tenant/app/volume: accepted move (fake_volume_move.go)

	registries []RegistryView

	apps    map[string]*fakeApp // tenant/app
	uploads map[string]*upload  // tenant/id
	events  []FixtureEvent
	evSeq   uint64
	evFloor uint64 // events with seq <= floor were trimmed

	execs map[string]*execRecord // user/requestID

	trust        map[string][]TrustRule             // tenant image sources (set-trust)
	ing          ingressState                       // REQ-22 (mock)
	ireal        ingressRealState                   // real REQ-22 book (fake_ingress_real.go)
	nodeDrains   map[string]control.NodeDrainStatus // node/operation (fake_node_ops_real.go)
	nodeDrainOps map[string][]string                // node → drain operations, registration order
	img          imageState                         // REQ-18 (mock)
	backupLimits []VolumeBackupLimit                // REQ-34
	compactHold  bool
	compactFail  map[string]string
	compactJobs  map[string]*FixtureRaftCompaction // raft-compact jobs by Operation

	standalones                       map[string]*standaloneEntry // tenant/name
	saMineMax, saTenantMax, saNodeMax int
	saControls                        map[string]control.TaskRestartStatus // REQ-29 tenant/name/operation

	creal        certRealState // REQ-21 catalogue (fake_certificates_real.go)
	ingressCerts []ingressCertObs
	ledger       map[string]ledgerEntry // user/requestID
	journal      []JournalEntry
}

func newWorld(f Fixture) *world {
	w := &world{
		cluster: f.Cluster, issuer: FixtureKey("issuer"), root: 100, ledgerEpoch: 1, retiring: map[string]string{}, retired: map[string]bool{},
		users: map[string]*fakeUser{}, tenants: map[string]map[string]Role{},
		tenantRev: map[string]uint64{}, tenantNodes: map[string][]string{}, revoked: map[string]bool{},
		members: f.Members, summaries: f.Summaries, disks: f.Disks, links: f.Links, raft: f.Raft,
		nodeStorage: f.NodeStorage, observeLimit: DefaultObserveLimitSeconds, resources: f.Resources, volumes: f.Volumes, backups: f.Backups,
		vault: slices.Clone(f.Vault), vaultRev: map[string]uint64{}, vaultWrites: map[string]*fakeVaultWrite{}, registries: f.Registries,
		apps: map[string]*fakeApp{}, uploads: map[string]*upload{}, ledger: map[string]ledgerEntry{}, execs: map[string]*execRecord{},
	}
	w.resources = slices.Clone(w.resources)
	fixtureMembers(w.resources)
	w.fixtureRoutes()
	w.fillVaultIDs()
	w.loadLifecycles(f)
	w.groupVerifiers, w.approvals = map[string]identity.PasswordVerifier{}, map[string]secrets.Target{}
	for _, k := range sortedKeys(f.GroupPasswords) {
		w.groupVerifiers[k] = fakeGroupVerifier(f.GroupPasswords[k])
	}
	w.routeOpen = map[string]bool{}
	for _, k := range f.RouteOpen {
		w.routeOpen[k] = true
	}
	w.fillVolumeSources()
	w.loadRegistries(time.Now().Unix())
	w.loadMembers()
	w.nodeCLI.Revision = 1
	for i, u := range f.Users {
		rec := User{ID: u.ID, Username: u.Username, Revision: uint64(10 + i), Enabled: u.Enabled, SystemAdmin: u.SystemAdmin}
		if u.Password != "" {
			rec.Credentials = append(rec.Credentials, Credential{ID: "password", Method: MethodPassword, VerifierRef: "vault:users/" + u.ID, Enabled: true})
		}
		if u.PrivateKey != nil {
			rec.Credentials = append(rec.Credentials, Credential{ID: "key-1", Method: MethodPrivateKey, PublicKey: pub32(u.PrivateKey), Enabled: true})
		}
		w.users[u.ID] = &fakeUser{rec: rec, secret: u.Password}
	}
	for i, t := range f.Tenants {
		m := map[string]Role{}
		for k, v := range t.Members {
			m[k] = v
		}
		w.tenants[t.ID] = m
		w.tenantRev[t.ID] = uint64(40 + i)
	}
	for k, v := range f.TenantNodes {
		w.tenantNodes[k] = append([]string(nil), v...)
	}
	for _, a := range f.Apps {
		w.root++
		app, err := w.deploy(a.Tenant, a.App, []byte(a.Document), a.Submitter, "seed-"+a.App, a.AcceptedAt)
		if err != nil {
			panic("mydc fake fixture app " + a.App + ": " + err.Error())
		}
		app.view.Health = a.Health
		app.view.CD = a.CD
		w.loadCD(app, a.Submitter)
		if app.view.CD != nil {
			app.seedCDHistory(a.Document, f.ImageCandidates[a.Tenant][a.App], a.AcceptedAt)
		}
		app.overrides = a.TaskOverrides
		app.applyOverrides()
	}
	for _, e := range f.Events {
		w.addEvent(e)
	}
	w.seedCertificates(f)
	w.seedStandalones(f)
	w.seedIngress(f)
	w.seedImages(f)
	w.extSeed, w.loginResult = slices.Clone(f.ExternalRegistries), map[string]string{}
	w.seedBuilds(f)
	w.tasksState = map[string]*taskState{}
	w.volGrantMeta, w.volJobs = map[string]volGrantMeta{}, map[string]*volFileJob{}
	w.nodeImages = map[string]map[string]fixtureNodeImage{}
	w.imageJobs = map[string]ImageCacheStatus{}
	w.volFiles = map[string]map[string]volFile{}
	for _, l := range f.BackupLimits {
		l.Owner = fakeNodeKey(l.Node)
		w.backupLimits = append(w.backupLimits, l)
	}
	w.trust = map[string][]TrustRule{}
	for k, v := range f.Trust {
		w.trust[k] = append([]TrustRule(nil), v...)
	}
	w.keyRoots, w.seedRoot, w.strictRoots = map[string]uint64{}, w.root, true
	return w
}

func (w *world) byName(username string) *fakeUser {
	for _, u := range w.users {
		if u.rec.Username == username {
			return u
		}
	}
	return nil
}

func (w *world) admin(user string) bool {
	u := w.users[user]
	return u != nil && u.rec.Enabled && u.rec.SystemAdmin
}

func (w *world) role(user, tenant string) (Role, bool) {
	m, ok := w.tenants[tenant]
	if !ok {
		return "", false
	}
	r, ok := m[user]
	return r, ok
}

func (w *world) canRead(user, tenant string) bool {
	if _, ok := w.tenants[tenant]; !ok {
		return false
	}
	if w.admin(user) {
		return true
	}
	_, ok := w.role(user, tenant)
	return ok
}

// canManageRealm: ManageSecrets on a Vault realm; realm "" is the cluster
// Vault, for system administrators only.
func (w *world) canManageRealm(user, realm string) bool {
	if realm == "" {
		return w.admin(user)
	}
	return w.canManage(user, realm)
}

func (w *world) canManage(user, tenant string) bool {
	if _, ok := w.tenants[tenant]; !ok {
		return false
	}
	if w.admin(user) {
		return true
	}
	r, _ := w.role(user, tenant)
	return r == RoleManager
}

func (w *world) scopes(user string) []Scope {
	var out []Scope
	for _, t := range sortedKeys(w.tenants) {
		r, ok := w.role(user, t)
		if !ok {
			continue
		}
		actions := []access.Action{access.Read}
		if r == RoleManager {
			actions = append(actions, access.Deploy, access.ManageNetwork, access.ManageSecrets, access.ManageVolumes,
				access.ManageRoutes, access.ManageCD, access.ManageRegistry, access.ManageTrust, access.ManageMembers)
		}
		out = append(out, Scope{Tenant: t, Actions: actions})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func digestOf(b []byte) [32]byte { return sha256.Sum256(b) }
