// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagesource"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Fixture is the seed state of a Fake. DefaultFixture matches the design
// canvas (작업 공간 shop/payments, 서버 node-a..node-d, 앱 php-shop 등).
// All data is fictional; passwords and keys here are for the fake only.
type Fixture struct {
	Cluster [32]byte
	Users   []FixtureUser
	Tenants []FixtureTenant
	// TenantNodes: servers each tenant may use (REQ-6 scope filter).
	TenantNodes map[string][]string

	Members     []FixtureMember
	Leader      string
	Summaries   []FixtureNodeSummary
	Disks       []FixtureDisk
	Links       []FixtureLink
	Raft        FixtureRaft
	NodeStorage []FixtureStorageRoot

	Resources []ResourceEntry
	Volumes   []volumeRow
	Backups   []VolumeBackupView
	Vault     []VaultView
	// GroupPasswords: "realm/group" → password of a protected Secret Group
	// (a deploy or standalone up that uses it waits for approval).
	GroupPasswords map[string]string
	// Lifecycle policies (current = last per tenant) and script records.
	LifecyclePolicies []checker.TenantPolicy
	LifecycleScripts  []FixtureLifecycleScript
	Registries        []FixtureRegistry

	// Apps are deployed through the same path as begin-app: the document is
	// parsed into services and tasks. Health/Restarts overrides apply after.
	Apps   []FixtureApp
	Events []FixtureEvent

	// REQ-21 (mock) certificate store and what each ingress serves.
	Certificates []FixtureCertificate
	// Domains are the cluster's registered domains (A-labels).
	Domains      []string
	IngressCerts []FixtureIngressCert

	// REQ-29 (mock) standalone containers.
	Standalones []FixtureStandalone

	// Trust: tenant image sources (set-trust rules), used by image-resolve.
	Trust map[string][]TrustRule

	// REQ-18 (mock) built-in registry images per tenant (Digest "" = derived)
	// and CD candidate image refs per tenant/app.
	Images          map[string][]RegistryImage
	ImageCandidates map[string]map[string]string

	// REQ-34 (mock) volume backup limits (Tenant "" = server-wide).
	BackupLimits []VolumeBackupLimit

	// REQ-22 (mock) ingress instances and each server's gateways.
	Ingresses       []IngressInstance
	IngressGateways map[string][]IngressGateway
	// NodeAddresses: the IPs each server really has (REQ-62: a gateway
	// address must be one of them). A server not listed is not checked.
	NodeAddresses map[string][]string

	// REQ-38 (mock) networks a tenant offers as route destinations
	// ("tenant/network"); the real policy is sfcd's.
	RouteOpen []string

	// REQ-17 external registry sources (bound to a server when Bound is
	// set, with one load OK pull on PullNode at PullAt); REQ-19 (mock) build
	// policies and contexts (Files: the content of every listed version).
	ExternalRegistries []FixtureExternalRegistry
	BuildPolicies      []BuildPolicy
	BuildContexts      []FixtureBuildContext
	// VPS seeds the VPS page and cost watch (fake_vps.go).
	VPS *FixtureVPS
}

type FixtureExternalRegistry struct {
	Source   imagesource.Source
	Bound    string // the reader's server ("" = not bound)
	PullNode string
	PullAt   int64
}

type FixtureBuildContext struct {
	Context BuildContext
	Files   map[string]string
}

// FixtureStandalone seeds one standalone container from its definition.
// Attached > 0 pretends a terminal is connected elsewhere (a temp one then
// does not end by grace).
type FixtureStandalone struct {
	Tenant, Owner, Document, State string
	Age                            time.Duration
	Restarts, Attached             int
	ExitCode                       *int
}

type FixtureUser struct {
	ID, Username string
	SystemAdmin  bool
	Enabled      bool
	// Password enables a "password" credential (fake only).
	Password string
	// PrivateKey enables a "private-key" credential with its public half.
	PrivateKey ed25519.PrivateKey
}

type FixtureTenant struct {
	ID      string
	Members map[string]Role // user ID → role
}

type FixtureApp struct {
	Tenant, App string
	Document    string
	Submitter   string
	AcceptedAt  int64
	Health      string
	// TaskOverrides by "service/instance".
	TaskOverrides map[string]Task
	CD            *AppCD
}

// FixtureKey derives a deterministic Ed25519 key for fixtures and tests.
func FixtureKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("sfc-web-fake-key\x00" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

const (
	gib = uint64(1) << 30
	mib = uint64(1) << 20
	// fixtureNow is 2026-11-21T09:00:00Z; seeded timestamps are relative to it.
	fixtureNow = int64(1795251600)
)

// privateSources: the default local gateway allowed sources (RFC 1918, ULA).
var privateSources = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

const phpShopYAML = `name: php-shop
x-sfc:
  lifecycle:
    scripts:
      ready:
        ref: {name: http-ready, revision: 2}
services:
  web:
    image: registry.sfc.local/shop/php-shop:1.4.2
    x-sfc:
      node: node-a
      lifecycle:
        checks:
          - id: ready
            phase: readiness
            script: ready
    networks: [shop-net]
  db:
    image: mysql:8.4
    x-sfc:
      node: node-b
    networks: [shop-net]
    volumes:
      - mysql-data:/var/lib/mysql
`

const shopWorkerYAML = `name: shop-worker
services:
  worker:
    image: registry.sfc.local/shop/worker:0.9.0
    x-sfc:
      node: node-b
    networks: [shop-net]
`

const paymentsAPIYAML = `name: payments-api
services:
  api:
    image: registry.sfc.local/payments/api:2.1.0
    x-sfc:
      node: node-c
    networks: [payments-net]
  redis:
    image: redis:7.4
    x-sfc:
      node: node-c
    networks: [payments-net]
`

// DefaultFixture: admin (password "admin", system admin), alice (password
// "alice", shop manager + payments viewer), bob (private key FixtureKey("bob"),
// shop viewer).
func DefaultFixture() Fixture {
	t := fixtureNow
	cluster := sha256.Sum256([]byte("sfc-web-fake-cluster"))
	return Fixture{
		Cluster: cluster,
		Users: []FixtureUser{
			{ID: "u-admin", Username: "admin", SystemAdmin: true, Enabled: true, Password: "admin"},
			{ID: "u-alice", Username: "alice", Enabled: true, Password: "alice"},
			{ID: "u-bob", Username: "bob", Enabled: true, PrivateKey: FixtureKey("bob")},
		},
		Tenants: []FixtureTenant{
			{ID: "shop", Members: map[string]Role{"u-alice": RoleManager, "u-bob": RoleViewer}},
			{ID: "payments", Members: map[string]Role{"u-alice": RoleViewer}},
		},
		TenantNodes: map[string][]string{
			"shop":     {"node-a", "node-b"},
			"payments": {"node-a", "node-c"},
		},
		Leader: "node-a",
		Members: []FixtureMember{
			{ID: "node-a", Key: keyHex(FixtureKey("node-a")), Endpoint: "10.0.0.11:7443", JoinID: "join-a", Revision: 3, Phase: NodePhaseActive, Voter: true, AdmitsWork: true},
			{ID: "node-b", Key: keyHex(FixtureKey("node-b")), Endpoint: "10.0.0.12:7443", JoinID: "join-b", Revision: 5, Phase: NodePhaseActive, Voter: true, AdmitsWork: true},
			{ID: "node-c", Key: keyHex(FixtureKey("node-c")), Endpoint: "10.0.0.13:7443", JoinID: "join-c", Revision: 7, Phase: NodePhaseActive, Voter: true, AdmitsWork: true},
			{ID: "node-d", Key: keyHex(FixtureKey("node-d")), Endpoint: "10.0.0.14:7443", JoinID: "join-d", Revision: 9, Phase: NodePhasePending, Voter: false, AdmitsWork: false, PendingOperation: "op-invite-node-d"},
		},
		Summaries: []FixtureNodeSummary{
			{Node: "node-a", Status: "ready", Role: "leader", CPUPercent: 31, MemUsed: 5 * gib, MemTotal: 16 * gib, DiskUsed: 120 * gib, DiskTotal: 400 * gib, ObservedAt: t},
			{Node: "node-b", Status: "ready", Role: "voter", CPUPercent: 58, MemUsed: 11 * gib, MemTotal: 16 * gib, DiskUsed: 350 * gib, DiskTotal: 400 * gib, ObservedAt: t},
			{Node: "node-c", Status: "degraded", Role: "voter", CPUPercent: 87, MemUsed: 14 * gib, MemTotal: 16 * gib, DiskUsed: 90 * gib, DiskTotal: 200 * gib, ObservedAt: t - 20},
			{Node: "node-d", Status: "unreachable", Role: "non-voter", ObservedAt: t - 600},
		},
		Disks: []FixtureDisk{
			{Node: "node-a", Mount: "/", Device: "/dev/sda1", FSType: "ext4", Purpose: "system", Total: 50 * gib, Used: 21 * gib, Free: 29 * gib, InodesFree: 2900000, ObservedAt: t},
			{Node: "node-a", Mount: "/var/lib/docker", Device: "/dev/sdb1", FSType: "xfs", Purpose: "container-runtime", Total: 350 * gib, Used: 99 * gib, Free: 251 * gib, InodesFree: 9000000, ObservedAt: t},
			{Node: "node-b", Mount: "/", Device: "/dev/sda1", FSType: "ext4", Purpose: "system", Total: 50 * gib, Used: 30 * gib, Free: 20 * gib, InodesFree: 2100000, ObservedAt: t},
			{Node: "node-b", Mount: "/var/lib/docker", Device: "/dev/sdb1", FSType: "xfs", Purpose: "container-runtime", Total: 200 * gib, Used: 170 * gib, Free: 30 * gib, InodesFree: 800000, ObservedAt: t},
			{Node: "node-b", Mount: "/srv/sfc-ssd", Device: "/dev/nvme0n1p1", FSType: "ext4", Purpose: "storage-root", StorageRootID: "ssd", Total: 150 * gib, Used: 140 * gib, Free: 10 * gib, InodesFree: 400000, ObservedAt: t},
			{Node: "node-c", Mount: "/", Device: "/dev/vda1", FSType: "ext4", Purpose: "system", Total: 200 * gib, Used: 90 * gib, Free: 110 * gib, InodesFree: 5000000, ObservedAt: t - 20},
		},
		Links: []FixtureLink{
			{NodeA: "node-a", NodeB: "node-b", State: "up", RTTMillis: 0.4, LastHandshakeAt: t - 40, LastChangeAt: t - 86400, ObservedBy: "node-a", ObservedAt: t},
			{NodeA: "node-a", NodeB: "node-c", State: "degraded", RTTMillis: 38, LossPercent: 4.5, LastHandshakeAt: t - 70, LastChangeAt: t - 900, ObservedBy: "node-a", ObservedAt: t},
			{NodeA: "node-b", NodeB: "node-c", State: "up", RTTMillis: 1.2, LastHandshakeAt: t - 30, LastChangeAt: t - 86400, ObservedBy: "node-b", ObservedAt: t},
			{NodeA: "node-a", NodeB: "node-d", State: "pending", ObservedBy: "node-a", ObservedAt: t},
		},
		Raft: FixtureRaft{
			Leader: "node-a", Term: 12, CommitIndex: 48210, ConfigurationIndex: 48001,
			LastSnapshotIndex: 47000, LastSnapshotAt: t - 3600,
			Servers: []FixtureRaftServer{
				{Node: "node-a", Suffrage: "voter", MatchIndex: 48210, AppliedIndex: 48210, LogBytes: 18 * mib, LastContactAt: t},
				{Node: "node-b", Suffrage: "voter", MatchIndex: 48210, AppliedIndex: 48209, Lag: 0, LogBytes: 18 * mib, LastContactAt: t},
				{Node: "node-c", Suffrage: "voter", MatchIndex: 48150, AppliedIndex: 48150, Lag: 60, LogBytes: 17 * mib, LastContactAt: t - 3},
			},
			Elections: []FixtureRaftElection{
				{Term: 11, Leader: "node-b", At: t - 7*86400, Reason: "leader-restart"},
				{Term: 12, Leader: "node-a", At: t - 2*86400, Reason: "leader-lost-contact"},
			},
		},
		NodeStorage: []FixtureStorageRoot{
			{Node: "node-b", ID: "ssd", Path: "/srv/sfc-ssd", Tenants: []string{"shop"}, CapacityBytes: 500 << 30, Generation: 1, Revision: 14, Attested: true},
			{Node: "node-c", ID: "hdd", Path: "/srv/sfc-hdd", Tenants: []string{"payments"}, Generation: 1, Revision: 15, Attested: true},
		},
		Resources: []ResourceEntry{
			{Key: "shop/network/shop-net", Tenant: "shop", Network: &Network{Name: "shop-net", Kind: "tun", CIDR: "10.20.0.0/24", Nodes: []string{"node-a", "node-b"}, Revision: 20}},
			// node-wide limits (tenant ""): the ceiling of every tenant limit
			{Key: "_cluster/limit/node-a", Limit: &NodeLimit{Node: "node-a", CPUs: 8, MemoryBytes: 32 * gib, Networks: 16, MaxConsumers: 256, Revision: 16}},
			{Key: "_cluster/limit/node-b", Limit: &NodeLimit{Node: "node-b", CPUs: 16, MemoryBytes: 64 * gib, Networks: 16, MaxConsumers: 256, Revision: 16}},
			{Key: "_cluster/limit/node-c", Limit: &NodeLimit{Node: "node-c", CPUs: 8, MemoryBytes: 32 * gib, Networks: 16, MaxConsumers: 256, Revision: 16}},
			{Key: "shop/limit/node-b", Tenant: "shop", Limit: &NodeLimit{Node: "node-b", CPUs: 4, MemoryBytes: 8 * gib, MaxContainers: 20, Networks: 4, MaxConsumers: 32, Revision: 18}},
			{Key: "payments/network/payments-net", Tenant: "payments", Network: &Network{Name: "payments-net", Kind: "tun", CIDR: "10.30.0.0/24", Nodes: []string{"node-a", "node-c"}, Revision: 21}},
		},
		Volumes: []volumeRow{
			{Key: "shop/mysql-data", Tenant: "shop", Name: "mysql-data", Kind: "fixed", Node: "node-b", Storage: "ssd", App: "php-shop", Revision: 25, Consumers: 1, CapacityBytes: 50 * gib, UsedBytes: 31 * gib, Retain: true},
			{Key: "shop/uploads", Tenant: "shop", Name: "uploads", Kind: "shared", Revision: 26, Consumers: 0, CapacityBytes: 10 * gib, UsedBytes: 2 * gib},
			// an app volume nothing mounts: what 보관 (archive-volume) takes
			{Key: "shop/sessions", Tenant: "shop", Name: "sessions", Kind: "shared", Node: "node-a", App: "php-shop", Revision: 34, CapacityBytes: 2 * gib, UsedBytes: 300 << 20},
			{Key: "payments/ledger-data", Tenant: "payments", Name: "ledger-data", Kind: "fixed", Node: "node-c", Storage: "hdd", Revision: 27, CapacityBytes: 100 * gib, UsedBytes: 12 * gib, Retain: true},
		},
		Backups: []VolumeBackupView{
			{Key: "shop/mysql-data/b-20261120", Tenant: "shop", Volume: "mysql-data", ID: "b-20261120", Node: "node-b", Phase: "Ready", Revision: 30, Bytes: 9 * gib, CreatedAt: t - 86400},
		},
		Vault: []VaultView{
			{Realm: "shop", Path: "db/mysql", Kind: "object", Profile: "default", Keys: []string{"MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD"}, Revision: 28, Group: "shop-db"},
			{Realm: "shop", Path: "registry/example", Kind: "object", Profile: "default", Keys: []string{"password", "username"}, Revision: 32},
			{Realm: "shop", Path: "ops/debug", Kind: "object", Profile: "default", Keys: []string{"DEBUG_TOKEN"}, Revision: 33, Group: "shop-ops"},
			{Realm: "payments", Path: "api/stripe", Kind: "object", Profile: "default", Keys: []string{"STRIPE_KEY"}, Revision: 29},
		},
		GroupPasswords:    map[string]string{"shop/shop-ops": "ops-pass"},
		LifecyclePolicies: []checker.TenantPolicy{FixtureLifecyclePolicy("shop")},
		LifecycleScripts:  fixtureLifecycleScripts(),
		Registries: []FixtureRegistry{
			{Tenant: "shop", ID: "builtin", Name: "내장 저장소", Endpoint: "registry.sfc.local", Revision: 19, Generation: 1, Active: true, Repositories: 2},
			{Tenant: "payments", ID: "builtin", Name: "내장 저장소", Endpoint: "registry.sfc.local", Revision: 19, Generation: 1, Active: true, Repositories: 1},
		},
		Apps: []FixtureApp{
			{Tenant: "shop", App: "php-shop", Document: phpShopYAML, Submitter: "alice", AcceptedAt: t - 3*3600, Health: "healthy",
				CD: &AppCD{Revision: 31, Repository: "https://git.example.invalid/shop/php-shop.git", Branch: "main", Mode: "manual", Running: "a1b2c3d", Candidate: "e4f5a6b"}},
			{Tenant: "shop", App: "shop-worker", Document: shopWorkerYAML, Submitter: "alice", AcceptedAt: t - 3600, Health: "degraded",
				TaskOverrides: map[string]Task{"worker/1": {Observed: "restarting", Health: "unhealthy", Restarts: 3, ExitCode: 137, LastCheck: "exit 137 (OOM)"}}},
			{Tenant: "payments", App: "payments-api", Document: paymentsAPIYAML, Submitter: "admin", AcceptedAt: t - 5*3600, Health: "healthy"},
		},
		Certificates: []FixtureCertificate{
			{SANs: []string{"shop.example.com", "www.shop.example.com"}, ValidDays: []int{20, 80}, UploadedBy: "admin"},
			{SANs: []string{"*.payments.example.com"}, ValidDays: []int{10}, UploadedBy: "admin"},
			{SANs: []string{"old.partner.example.net"}, ValidDays: []int{40}, UploadedBy: "admin"},
		},
		Domains: []string{"payments.example.com", "shop.example.com"},
		IngressCerts: []FixtureIngressCert{
			{Node: "node-a", Listener: "0.0.0.0:443", Host: "shop.example.com"},
			{Node: "node-b", Listener: "0.0.0.0:443", Host: "shop.example.com"},
			{Node: "node-c", Listener: "0.0.0.0:443", Host: "api.payments.example.com"},
			{Node: "node-c", Listener: "0.0.0.0:443", Host: "admin.payments.example.com"},
		},
		BackupLimits: []VolumeBackupLimit{
			{Node: "node-b", Revision: 2, Bytes: 200 * gib, Count: 50, StagingBytes: 20 * gib, StagingCount: 4},
			{Tenant: "shop", Node: "node-b", Revision: 1, Bytes: 100 * gib, Count: 20, StagingBytes: 10 * gib, StagingCount: 2},
			{Node: "node-a", Revision: 1, Bytes: 100 * gib, Count: 30, StagingBytes: 10 * gib, StagingCount: 2},
			{Node: "node-c", Revision: 1, Bytes: 100 * gib, Count: 30, StagingBytes: 10 * gib, StagingCount: 2},
			{Tenant: "payments", Node: "node-c", Revision: 1, Bytes: 50 * gib, Count: 10, StagingBytes: 5 * gib, StagingCount: 1,
				Original: &control.OriginalVolumeLimit{Bytes: 20 * gib, Count: 2}}, // a move budget
		},
		Images: map[string][]RegistryImage{
			"shop": {
				{Repository: "shop/php-shop", Tags: []string{"1.4.3"}, Bytes: 212 << 20, PushedAt: t - 1800},
				{Repository: "shop/php-shop", Tags: []string{"1.4.2", "stable"}, Bytes: 210 << 20, PushedAt: t - 3*86400},
				{Repository: "shop/php-shop", Tags: []string{"1.4.1"}, Bytes: 209 << 20, PushedAt: t - 9*86400},
				{Repository: "shop/php-shop", Tags: []string{"1.4.0"}, Bytes: 208 << 20, PushedAt: t - 20*86400},
				{Repository: "shop/php-shop", Bytes: 207 << 20, PushedAt: t - 25*86400},
				{Repository: "shop/worker", Tags: []string{"0.9.0"}, Bytes: 95 << 20, PushedAt: t - 2*86400},
				{Repository: "shop/worker", Tags: []string{"0.8.5"}, Bytes: 94 << 20, PushedAt: t - 40*86400},
			},
			"payments": {
				{Repository: "payments/api", Tags: []string{"2.1.0"}, Bytes: 120 << 20, PushedAt: t - 5*86400},
				{Repository: "payments/api", Tags: []string{"2.0.3"}, Bytes: 118 << 20, PushedAt: t - 30*86400},
			},
		},
		ImageCandidates: map[string]map[string]string{"shop": {"php-shop": "registry.sfc.local/shop/php-shop:1.4.3"}},
		RouteOpen:       []string{"payments/payments-net"},
		VPS:             DefaultVPSFixture(),
		ExternalRegistries: []FixtureExternalRegistry{
			{Source: imagesource.Source{Tenant: "shop", ID: "example", Authority: "registry.example.com", Repository: "shop/**", Enabled: true, Auth: "password",
				Credential: &imagesource.Credential{Realm: "shop", ID: "example", UsernameKey: "username", PasswordKey: "password"}},
				Bound: "node-a", PullNode: "node-a", PullAt: t - 600},
		},
		BuildPolicies: []BuildPolicy{{Tenant: "shop", Revision: 34, Nodes: []string{"node-a"}, Concurrent: 2, TimeoutSeconds: 1800, CPUs: 2,
			MemoryBytes: 4 * gib, ScratchBytes: 10 * gib, CacheBytes: 20 * gib, Registry: ImageRegistryBuiltin, Platforms: []string{"linux/amd64"}}},
		BuildContexts: []FixtureBuildContext{
			{Context: BuildContext{Tenant: "shop", ID: "cron", Name: "주기 작업", Kind: BuildInline, Revision: 35, Version: 1, Versions: []uint64{1},
				Dockerfile: "Dockerfile", Repository: "shop/cron", TagRule: "{version}", Platforms: []string{"linux/amd64"}},
				Files: map[string]string{"Dockerfile": "FROM docker.io/library/busybox:1.36\nCOPY crontab /etc/crontabs/root\nCMD [\"crond\", \"-f\"]\n", "crontab": "*/5 * * * * /bin/true\n"}},
			{Context: BuildContext{Tenant: "shop", ID: "web", Name: "쇼핑몰 웹", Kind: BuildGit, Revision: 36, Version: 1, Versions: []uint64{1},
				Git:        &BuildGitSource{Repository: "https://git.example.invalid/shop/php-shop.git", Ref: "refs/heads/main", Commit: "e4f5a6b", AutoBuild: true},
				Dockerfile: "Dockerfile", Repository: "shop/php-shop", TagRule: "{commit}", Platforms: []string{"linux/amd64"}},
				Files: map[string]string{"Dockerfile": "FROM docker.io/library/busybox:1.36\nCOPY public/ /var/www/\n", "public/index.php": "<?php echo 'shop';\n"}},
			{Context: BuildContext{Tenant: "shop", ID: "worker", Name: "작업 처리기", Kind: BuildUpload, Revision: 37, Version: 2, Versions: []uint64{1, 2},
				Dockerfile: "Dockerfile", Repository: "shop/worker", TagRule: "{version}", Platforms: []string{"linux/amd64"},
				Args:    []BuildArg{{Name: "APP_ENV", Value: "production"}, {Name: "NPM_TOKEN", Secret: &BuildSecretRef{Realm: "shop", Object: "example", Key: "password"}}},
				Secrets: []BuildSecret{{ID: "db", Realm: "shop", Object: "mysql", Key: "MYSQL_PASSWORD"}}},
				Files: map[string]string{"Dockerfile": "FROM docker.io/library/busybox:1.36\nARG APP_ENV\nCOPY bin/ /usr/local/bin/\n", "bin/worker": "#!/bin/sh\nexec sleep 3600\n"}},
		},
		IngressGateways: map[string][]IngressGateway{
			"node-a": {{Kind: GatewayExternal, Addresses: []string{"203.0.113.11"}, Ports: []int{80, 443}, Enabled: true, State: "up"},
				{Kind: GatewayLocal, Addresses: []string{"10.0.0.11"}, Ports: []int{443}, AllowedSources: privateSources, Enabled: true, State: "up", RejectedSources: 12}},
			"node-b": {{Kind: GatewayExternal, Addresses: []string{"203.0.113.12"}, Ports: []int{443}, Enabled: true, State: "up"},
				{Kind: GatewayLocal, Addresses: []string{"10.0.0.12"}, Ports: []int{443}, AllowedSources: privateSources, Enabled: true, State: "up"}},
			"node-c": {{Kind: GatewayLocal, Addresses: []string{"10.0.0.13"}, Ports: []int{443}, AllowedSources: privateSources, Enabled: true, State: "up", RejectedSources: 3}},
		},
		NodeAddresses: map[string][]string{
			"node-a": {"203.0.113.11", "203.0.113.21", "10.0.0.11", "10.0.0.21"},
			"node-b": {"203.0.113.12", "203.0.113.22", "10.0.0.12", "10.0.0.22"},
			"node-c": {"203.0.113.23", "10.0.0.13", "10.0.0.23"},
		},
		Ingresses: []IngressInstance{
			{Tenant: "shop", App: "php-shop", Node: "node-a", Generation: 4, Ready: true,
				Listeners: []IngressListener{
					{ID: "shared-a-ext-443", Address: "203.0.113.11:443", Gateway: GatewayExternal, Shared: true, Protocols: []string{"h1", "h2", "h3"}, TLS: true, HTTP3: true, State: "listening"},
					{ID: "shared-a-local-443", Address: "10.0.0.11:443", Gateway: GatewayLocal, Shared: true, Protocols: []string{"h1", "h2"}, TLS: true, State: "listening"},
				},
				Routes: []IngressRoute{
					{ID: "shop-root", Host: "shop.example.com", Prefix: "/", Service: "web", Gateway: GatewayExternal, Balance: IngressBalance{Method: "round-robin"}},
					{ID: "shop-admin", Host: "shop.example.com", Prefix: "/admin", Service: "web", Gateway: GatewayLocal, Balance: IngressBalance{Method: "least-request", Locality: "same-node"}},
				},
				Backends: []IngressBackend{{Service: "web", Task: "shop/php-shop/web/1", Node: "node-a", Network: "shop-net", Address: "10.20.0.5", Port: 8080, Weight: 100, Generation: 4, Healthy: true, LastCheckAt: t - 5}}},
			{Tenant: "shop", App: "php-shop", Node: "node-b", Generation: 4, Ready: true,
				Listeners: []IngressListener{
					{ID: "shared-b-ext-443", Address: "203.0.113.12:443", Gateway: GatewayExternal, Shared: true, Protocols: []string{"h1", "h2"}, TLS: true, State: "listening"},
				},
				Routes: []IngressRoute{
					{ID: "shop-root", Host: "shop.example.com", Prefix: "/", Service: "web", Gateway: GatewayExternal, Balance: IngressBalance{Method: "round-robin"}},
				},
				Backends: []IngressBackend{{Service: "web", Task: "shop/php-shop/web/1", Node: "node-a", Network: "shop-net", Address: "10.20.0.5", Port: 8080, Weight: 100, Generation: 4, Healthy: true, LastCheckAt: t - 5}}},
			{Tenant: "payments", App: "payments-api", Node: "node-c", Generation: 2, Ready: true, Error: "no certificate for admin.payments.example.com",
				Listeners: []IngressListener{
					{ID: "shared-c-local-443", Address: "10.0.0.13:443", Gateway: GatewayLocal, Shared: true, Protocols: []string{"h1", "h2"}, TLS: true, State: "listening"},
				},
				Routes: []IngressRoute{
					{ID: "pay-api", Host: "api.payments.example.com", Prefix: "/", Service: "api", Gateway: GatewayLocal, Balance: IngressBalance{Method: "hash", Key: "cookie:session"}},
					{ID: "pay-admin", Host: "admin.payments.example.com", Prefix: "/", Service: "api", Gateway: GatewayLocal, Balance: IngressBalance{Method: "round-robin"}},
				},
				Backends: []IngressBackend{{Service: "api", Task: "payments/payments-api/api/1", Node: "node-c", Network: "payments-net", Address: "10.30.0.4", Port: 9000, Weight: 100, Generation: 2, Healthy: true, LastCheckAt: t - 8}}},
		},
		Trust: map[string][]TrustRule{
			"shop": {{Registry: "registry.sfc.local", Repository: "**"}, {Registry: "docker.io", Repository: "library/mysql"},
				{Registry: "docker.io", Repository: "library/busybox"}, {Registry: "registry.example.com", Repository: "shop/cron"}},
			"payments": {{Registry: "registry.sfc.local", Repository: "**"}, {Registry: "docker.io", Repository: "library/redis"},
				{Registry: "registry.example.com", Repository: "payments/migrate"}},
		},
		Standalones: []FixtureStandalone{
			{Tenant: "shop", Owner: "u-alice", State: "running", Age: 30 * 24 * time.Hour, Restarts: 1, Document: `name: shop-cron
lifetime: fixed
restart: on-failure
mode: entrypoint
image: registry.example.com/shop/cron:1.4
command: ["cron", "-f"]
networks: [shop-net]
x-sfc: {node: node-a}
`},
			{Tenant: "shop", Owner: "u-alice", State: "running", Age: 20 * time.Minute, Attached: 1, Document: `name: alice-debug
lifetime: temp
ttl: 8h
grace: 10m
mode: shell
image: busybox:1.36
networks: [shop-net]
x-sfc: {node: node-b}
`},
			{Tenant: "payments", Owner: "u-admin", State: "exited", Age: 2 * 24 * time.Hour, ExitCode: new(int), Document: `name: ledger-migrate
lifetime: fixed
restart: "no"
mode: entrypoint
image: registry.example.com/payments/migrate:3.2
command: ["migrate", "up"]
volumes: ["ledger-data:/data:ro"]
x-sfc: {node: node-c}
`},
		},
		Events: []FixtureEvent{
			{Time: t - 1500, Scope: "app", Tenant: "shop", App: "shop-worker", Node: "node-b", Kind: "task-restarted", Target: "shop/shop-worker/worker/1", Detail: "exit 137"},
			{Time: t - 1200, Scope: "app", Tenant: "shop", App: "shop-worker", Node: "node-b", Kind: "task-restarted", Target: "shop/shop-worker/worker/1", Detail: "exit 137"},
			{Time: t - 900, Scope: "tenant", Tenant: "payments", Network: "payments-net", Node: "node-c", PairID: "node-a/node-c", Kind: "tunnel-down", Target: "node-a/node-c", Detail: "AUTHENTICATED_LINK_DOWN"},
			{Time: t - 600, Scope: "app", Tenant: "shop", App: "shop-worker", Node: "node-b", Kind: "task-restarted", Target: "shop/shop-worker/worker/1", Detail: "exit 137"},
			{Time: t - 300, Scope: "node", Node: "node-b", Kind: "node-resource-low", Target: "node-b:/srv/sfc-ssd", Detail: "disk 93%"},
		},
	}
}
