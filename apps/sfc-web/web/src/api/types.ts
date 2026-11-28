// SPDX-License-Identifier: Apache-2.0

// 화면용 보기 모델. 계약 DTO(dto.ts)를 endpoints.ts가 이 모양으로 바꾼다.
// 시각은 모두 ISO 문자열로 맞춘다(sfcd Unix 초는 변환).

export interface ApiErrorBody {
  code: string;
  message?: string;
  inputCode?: string;
  leader?: string;
  raw?: unknown;
}

export interface Page<T> {
  items: T[];
  next: string;
  revision: number;
  asOf: string;
}

// ── 인증 ────────────────────────────────────────────────

export interface UserView {
  id: string;
  username: string;
  revision: number;
  systemAdmin: boolean;
}
export type TenantRole = 'manager' | 'viewer';
export interface TenantAccess {
  id: string;
  role: TenantRole;
  revision: number;
}
export interface SessionView {
  user: UserView;
  tenants: TenantAccess[];
  expiresAt: string;
  method: 'password' | 'token' | 'key';
  rootRevision: number;
}
export type CredentialMethod = 'password' | 'token';

export interface CredentialChallengeReply {
  ticketId: string;
  deadline?: string;
}

export interface UserCredential {
  id: string;
  kind: 'password' | 'token' | 'key';
  publicKey?: string;
  enabled: boolean;
  label?: string;
  createdAt?: string;
  createdBy?: string;
  lastUsedAt?: string;
  expiresAt?: string;
  tail?: string;
  approvalKey?: boolean;
}
export interface OwnCredentials {
  userId: string;
  username: string;
  accountRevision: number;
  /** 본인 add-credential 증명에 쓰는 클러스터 ID(64자 hex) */
  clusterId?: string;
  credentials: UserCredential[];
}

// ── 작업(operation) ─────────────────────────────────────

export type OpState = 'applied' | 'failed' | 'rejected' | 'unknown' | 'pending' | 'running';
export const ResultCodeName: Record<number, string> = {
  0: '적용됨',
  1: '조건 불일치(버전 바뀜)',
  2: '잘못된 요청',
  3: '요청 충돌',
  4: '권한 없음',
  5: '만료',
  6: '기록 공간 부족',
};
export interface OpView {
  id: string;
  requestId?: string;
  batch?: string;
  action: string;
  target: string;
  tenant?: string;
  state: OpState;
  errorCode?: string;
  resultFound?: boolean;
  resultCode?: number;
  index?: number;
  revision?: number;
  submittedAt: string;
  updatedAt: string;
  parent?: string;
  step?: number;
  steps?: number;
  approvals?: GroupApproval[];
  revert?: 'here' | 'link' | 'no';
  revertOf?: string;
}
export interface GroupApproval {
  realm: string;
  group: string;
  services: string[];
  state: 'required' | 'approved' | 'unknown';
}
export interface PendingApproval extends GroupApproval {
  opId: string;
  kind: 'deploy' | 'build' | 'registry-bind' | 'standalone';
  app: string;
  /** standalone 행: 단독 컨테이너 이름 */
  standalone?: string;
  context?: string;
  build?: string;
  source?: string;
  node?: string;
  updatedAt: string;
}
export interface GrantedApproval {
  id: string;
  realm: string;
  group: string;
  user: string;
  app?: string;
  standalone?: string;
  deployment?: string;
  purpose?: string;
  services: string[];
  nodes: string[];
  approvedAt: string;
  expiresAt?: string;
  issuer: string;
  /** 철회가 받아들여져 쓰는 곳을 돌려받는 중(끝나면 목록에서 빠진다) */
  revoking: boolean;
  consumers?: number;
}
export interface OpReply {
  op: OpView;
}

// ── 서버 ────────────────────────────────────────────────

/** waiting: 이번 조회에서 서버가 2초 안에 답하지 않아 그 전 값을 보임(R18) */
export type NodePhase = 'ready' | 'joining' | 'isolated' | 'removing' | 'problem' | 'unknown' | 'waiting';
export interface Usage {
  used: number;
  total: number;
}
export interface NodeView {
  id: string;
  endpoint?: string;
  /** 서버 고정 주소(망 터널 주소로 씀) */
  systemAddress?: string;
  key?: string;
  phase: NodePhase;
  /** 단계가 오류(problem)일 때 그 사유(사람이 읽는 글) */
  phaseReason?: string;
  /** 오류가 이어진 시작 시각(ISO, 관리자만) */
  failingSince?: string;
  voter: boolean;
  leader: boolean;
  /** 작업 공간 보기라 역할을 받지 못함(데몬 #373) */
  roleUnknown?: boolean;
  /** 총량 없이 사용량만 받은 메모리(작업 공간 보기) */
  memUsed?: number;
  /** 오래된 관측 */
  stale?: boolean;
  admitsWork?: boolean;
  cordoned?: boolean;
  cordonReason?: string;
  cordonedBy?: string;
  cordonedAt?: string;
  drain?: import('./dto').DNodeDrainProgress;
  observeLimitSeconds?: number;
  identity?: import('./dto').DMember['identity'];
  identityRotatedAt?: string;
  revision?: number;
  /** promote의 expected */
  joinRevision?: number;
  /** 막기·풀기의 expected */
  schedulingRevision?: number;
  cpuPercent?: number;
  /** 공유 VPS에서 다른 VM이 가져간 CPU 몫(0–100). 없거나 0이면 숨긴다 */
  cpuStealPercent?: number;
  memory?: Usage;
  disk?: Usage;
  containers?: number;
  /** 클러스터 앱(클러스터 전체 보기에서만). undefined면 켠 클러스터 앱이 없거나 볼 수 없음 */
  clusterApps?: import('./dto').DClusterApp[];
  observedAt?: string;
  pendingOperation?: string;
  join?: string;
  /** 빌드할 수 있는지(#693). 없으면 웹이 아직 알려 주지 않음 */
  build?: { enabled: boolean; reason?: string };
}
export interface NodesOverview {
  nodes: NodeView[];
  voters?: number;
  quorum?: number;
  revision: number;
  asOf: string;
}

export interface TaskView {
  id: string;
  tenant: string;
  app: string;
  service: string;
  instance: string;
  node: string;
  image: string;
  desired: 'running' | 'stopped';
  observed: 'running' | 'starting' | 'restarting' | 'exited' | 'unknown';
  health: 'pass' | 'fail' | 'starting' | 'none';
  generation: number;
  restarts: number;
  startedAt?: string;
  exitCode?: number;
  observedAt: string;
  stale: boolean;
  lastCheck?: string;
  /** 단독 컨테이너면 그 이름. 스트림·터미널 경로가 앱 대신 단독 컨테이너 경로가 된다. */
  standalone?: string;
}

export interface StorageRoot {
  node: string;
  name: string;
  path: string;
  tenants: string[];
  draining: boolean;
  revision: number;
  generation: number;
  /** 모든 작업 공간이 쓴다(tenants는 빈 배열) */
  allTenants?: boolean;
  /** 고정 데이터 저장소 예약 합의 상한. 0 = 한도 없음, 작업 공간 행에는 없음(모름) */
  capacityBytes?: number;
  /** 서버가 스스로 등록한 기본 저장 경로(id "default") */
  isDefault?: boolean;
  closed?: boolean;
  attested?: boolean;
  volumes?: number;
  /** 작업 공간 행(GET /t/{t}/storage)만: 이 작업 공간이 새로 쓸 수 있는지 */
  allowed?: boolean;
  /** 그 서버의 기본 보관 위치(내린 앱 저장소 보관의 store 기본값) */
  archiveDefault?: boolean;
}

export interface DiskView {
  root?: string;
  /** 이 파일 시스템에 있는 저장 경로 전부 */
  roots: string[];
  mount: string;
  /** 작업 공간 보기에는 없다 */
  device?: string;
  fs: string;
  purpose: string;
  /** 관측 전이면 없다 */
  total?: number;
  used?: number;
  free?: number;
  stale?: boolean;
}

export interface RaftView {
  quorum: boolean;
  leader: string;
  term: number;
  commitIndex: number;
  configIndex: number;
  voters: number;
  quorumSize: number;
  tolerate: number;
  /** 응답한 투표 서버 수(데몬 #367). 옛 데몬은 없음 */
  responding?: number;
  /** 이 값을 관측한 서버. 마지막 스냅샷도 이 서버 값 */
  observedBy?: string;
  snapshotIndex?: number;
  snapshotAt?: string;
  members: { node: string; voter: boolean; role?: string; match?: number; applied?: number; lag?: number; logBytes?: number; logEntries?: number; lastContactAt?: string; stale?: boolean }[];
  events: { at: string; text: string }[];
}

export interface MeshLink {
  a: string;
  b: string;
  state: 'up' | 'slow' | 'down' | 'pending';
  rttMs?: number;
  lossPct?: number;
  observedAt: string;
  stale?: boolean;
  /** 지금 세션을 연 서버(a 또는 b). 데몬이 알려 줄 때만 */
  dialer?: string;
}

// ── 대시보드 ────────────────────────────────────────────

export interface AttentionItem {
  kind: 'approval' | 'problem' | 'disk' | 'unknown-op' | 'progress' | 'incident' | 'ingress-block' | 'cert' | 'webhook';
  text: string;
  at: string;
  link?: string;
}
export interface DashboardView {
  scope: 'cluster' | 'tenant';
  nodes: NodeView[];
  apps: AppView[];
  attention: AttentionItem[];
  asOf: string;
}

// ── 작업 공간 · 사용자 ─────────────────────────────────

export interface TenantMember {
  user: string;
  username: string;
  role: TenantRole;
  enabled: boolean;
  revision: number;
}
export interface TenantRetirement {
  retiring: boolean;
  targetCount: number;
  ownerCount: number;
  closedOwners: number;
  remainingCount: number;
  remaining: string[];
  operation?: string;
  revision?: number;
  phase?: string;
  ready: boolean;
}
export interface NodeLimit {
  node: string;
  cpus: number;
  memoryBytes: number;
  maxContainers: number;
  revision: number;
  nodeCpus?: number;
  nodeMemoryBytes?: number;
}
export interface UserRecord {
  id: string;
  username: string;
  enabled: boolean;
  systemAdmin: boolean;
  revision: number;
  credentials: UserCredential[];
  /** 계정 revision(초대 회수의 expected) */
  accountRevision?: number;
  invite?: { state: 'active' | 'expired'; expiresAt: string };
}

// ── 앱 ──────────────────────────────────────────────────

export type Health = 'healthy' | 'progressing' | 'degraded' | 'unhealthy' | 'unknown';
export interface AppView {
  tenant: string;
  app: string;
  deployment: string;
  revision: number;
  health: Health;
  /** 상태 배지 옆 사유 한 줄(예: worker 종료 코드 1 · node-b) */
  reason?: string;
  retiring: boolean;
  lastOp?: { id: string; status: string; failed: boolean; at?: string; submitter?: string };
  cd?: { repository: string; branch: string; mode: string; paused: boolean; running?: string; sourceError?: string; candidate?: string; candidateDigest?: string };
  observedAt?: string;
  claims: number;
}
export interface AppSource {
  version: number;
  yaml: string;
  digest: string;
  submitter: string;
  operation: string;
  acceptedAt?: string;
}
export interface AppRevision {
  version: number;
  digest: string;
  submitter: string;
  operation: string;
  status: string;
  at: string;
}
export interface DiffLine {
  op: ' ' | '+' | '-';
  text: string;
}
export interface PlanReply {
  app: string;
  digest: string;
  length: number;
  services: { name: string; image: string; node: string; change: 'add' | 'update' | 'remove' | 'keep' }[];
  counts: { add: number; change: number; keep: number; remove: number };
  diff: DiffLine[];
  /** 바뀐 항목(Z9). 예전 데몬이면 빈 배열 */
  changes: { action: string; key: string; reason?: string; interruption?: string }[];
}
export interface ArchivedApp {
  key: string;
  tenant: string;
  app: string;
  version: number;
  digest: string;
  downBy: string;
  downAt: string;
  downOp: string;
  volumes: string[];
}
export interface UploadView {
  id: string;
  app: string;
  deployment: string;
  parts: number;
  missing: number[];
}

// ── 공유 자원 ───────────────────────────────────────────

/** 망 도메인 이름 정책. zone·enabled·revision 밖의 칸은 데몬이 주기 시작하면 채워진다 */
export interface NetworkDnsView {
  zone: string;
  enabled: boolean;
  revision: number;
  upstreams?: string[];
  ttl?: number;
  negativeTtl?: number;
  reverse?: boolean;
  /** 망 안에서 이름을 묻는 주소(서버마다 하나일 수 있음) */
  resolver?: string;
}
export interface NetworkView {
  key: string;
  name: string;
  kind: 'bridge' | 'tun';
  cidr: string;
  nodes: string[];
  revision: number;
  /** 망 도메인 이름. zone은 끝 점을 뗀 모양 */
  dns?: NetworkDnsView;
  /** 켜진 망 옵션(set-network-toggle). local = 이 서버에서만 쓰는 망 */
  toggles: string[];
  /** 서버별 멤버(이전 데몬은 비어 있음). 변경 중이면 change가 붙는다 */
  members: { node: string; cidr: string; draining: boolean; phase?: string; resolver?: string; dns?: { state: string; ready?: boolean; resolvers: string[] } }[];
  /** 이 망을 쓰는 앱·단독 컨테이너 수(이전 데몬은 없음) */
  apps?: number;
  standalones?: number;
}
export interface VolumeView {
  key: string;
  name: string;
  kind: 'shared' | 'fixed';
  node?: string;
  storage?: string;
  app?: string;
  consumers: number;
  capacityBytes?: number;
  /** 없으면 모름 */
  usedBytes?: number;
  usageObservedAt?: string;
  retain: boolean;
  revision: number;
  phase?: string;
  movePhase?: string;
  targetNode?: string;
  moveId?: string;
  /** 보관이 잡고 있으면 그 보관 ID·단계(#920) */
  archiveId?: string;
  archivePhase?: string;
  retained: { moveID: string; node: string; state: 'retained' | 'deleting' | 'removed' }[];
  writer?: string;
}
export interface VaultACL {
  users: string[];
  services: string[];
  denyUsers: string[];
  denyServices: string[];
}
export interface VaultUsage {
  id?: string;
  user?: string;
  app?: string;
  deployment?: string;
  service?: string;
  standalone?: string;
  node: string;
  purpose?: string;
  secrets: string[];
  live: boolean;
}
export interface SecretView {
  realm: string;
  path: string;
  kind: 'object' | 'group';
  profile: string;
  keys: string[];
  group?: string;
  revision: number;
  /** sfcd 객체 ID(이전 데몬은 path 끝)와 부모 ID(최상위는 작업 공간 이름) */
  id: string;
  parent: string;
  status: 'active' | 'password-pending' | 'revoking' | 'retired' | 'reference-pending';
  acl: VaultACL;
  protected: boolean;
  pendingWrite?: string;
  maxApprovalAge?: number;
}
export interface LifecycleView {
  name: string;
  recordRevision: number;
  activeRevision: number;
  latestRevision: number;
  versions: { revision: number; active: boolean; deleted: boolean; digest: string; length: number; modules: { path: string; version: string }[] }[];
}
export interface RegistryView {
  id: string;
  name: string;
  endpoint: string;
  repositories: number;
  active: boolean;
  revision: number;
  node?: string;
  address?: string;
  /** 노드가 지금 쓴다고 보고한 보관함 인증서 ID(64자 hex). 보고 전에는 없음 */
  certificateID?: string;
  volume?: string;
  enabled?: boolean;
  deleted?: boolean;
  status?: import('./dto').RegistryStatus;
  observedAt?: number;
  limits?: import('./dto').DRegistryLimits;
  maintenance?: import('./dto').DRegistryMaintenance;
}
/** 이미지 목록은 웹 캐시. 지금은 목업에만 있다. */
export interface ImageView {
  registry: string;
  repo: string;
  tag: string;
  digest: string;
  sizeBytes: number;
  pushedAt: string;
  usedBy: string[];
  /** 작업 공간 신뢰 정책 결과(있을 때만) */
  trusted?: boolean;
}

// ── 알림 (UI-C0) ────────────────────────────────────────

export interface NotificationView {
  id: string;
  kind: string;
  severity: 'info' | 'warning' | 'error';
  tenant?: string;
  title: string;
  text: string;
  at: string;
  read: boolean;
  link?: string;
  /** 지금 내가 할 일 */
  todo: boolean;
}

// ── 단독 컨테이너 ──
export interface StandaloneView {
  name: string;
  tenant: string;
  lifetime: 'temp' | 'fixed';
  mode: 'shell' | 'entrypoint';
  image: string;
  node: string;
  state: 'running' | 'exited' | 'restarting' | 'starting' | 'pending' | 'unknown' | 'removed';
  exitCode?: number;
  restarts: number;
  restartPolicy?: 'no' | 'on-failure' | 'always';
  expiresAt?: string;
  graceSeconds?: number;
  disconnectedAt?: string;
  endedAt?: string;
  digest?: string;
  connections: number;
  owner: string;
  ownerName: string;
  revision: number;
  yaml: string;
  createdAt?: string;
  observedAt?: string;
  operation?: string;
  importedFrom?: { app: string; deployment?: string; service: string; items: string[]; by: string; at?: string };
}
export interface StandalonePlanView {
  name: string;
  revision: number;
  recreate: boolean;
  create: boolean;
  changes: { field: string; change: 'add' | 'update' | 'remove' }[];
  impact: { kind: string; name: string; level: 'info' | 'block'; text: string }[];
  limits?: { mine: number; mineMax: number; tenant: number; tenantMax: number; node?: number; nodeMax?: number };
  diff: DiffLine[];
}

/** 이미지 참조 확인 */
export interface ImageResolveView {
  ref: string;
  /** 주소(host[:port]). 내장인지는 registryKind로 본다 (#237) */
  registry?: string;
  registryKind: 'builtin' | 'external' | 'unknown';
  /** 내장/외부 정의 이름 */
  source?: string;
  digest?: string;
  mediaType?: string;
  trusted?: boolean;
  reason?: string;
  /** 신뢰 안 될 때 보여 줄 이 작업 공간의 신뢰 규칙 */
  rules?: { registry: string; repository: string }[] | null;
  /** 없으면 풀림. untrusted, source-revoked, source-not-ready, unauthorized, denied, not-found, unavailable, … */
  code?: string;
  /** 데몬 #118: 받은 그대로의 입력, authority/repository@digest, 멀티 플랫폼 목록 */
  input?: string;
  pinned?: string;
  platforms?: { platform?: string; digest: string }[] | null;
}

/** 가상 브릿지 (UI-5D). ports·approvals는 빈 배열로 채운다 */
export type BridgeView = Omit<import('./dto').DBridge, 'ports' | 'approvals'> & { key: string; ports: { first: number; last: number }[]; approvals: { tenant: string; user: string }[] };
