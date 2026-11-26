// SPDX-License-Identifier: Apache-2.0

import type { CdGate } from './webhooks';
// mydc-web /api/v1 응답 DTO. 계약: docs/reference/web-api.md
// mydcd 타입의 필드는 첫 대문자 덩어리만 소문자로 바뀐다(ID→id, CPUPercent→cpuPercent).
// [32]byte는 hex, []byte는 base64, mydcd 시각은 Unix 초, 웹이 만든 시각은 RFC 3339.

export interface ListPage<T> {
  items: T[];
  next?: string;
  revision: number;
  asOf: string;
}

export interface DUserView {
  id: string;
  username: string;
  revision: number;
  systemAdmin: boolean;
}
export interface DTenantView {
  id: string;
  revision: number;
  role: 'manager' | 'viewer';
}
export interface DSession {
  user: DUserView;
  tenants: DTenantView[];
  expiresAt: string;
  method: 'password' | 'token' | 'key' | 'private-key';
  rootRevision?: number;
}

/** mydcd userauth.Ticket(camel). [32]byte는 hex, 시각은 Unix 초. */
export interface DTicket {
  schema?: number;
  user?: string;
  username: string;
  credential?: string;
  accountRevision?: number;
  userKey?: string;
  nonce?: string;
  issuer?: string;
  issuedAt?: number;
  deadline: number;
  authMethod?: string;
}
/** key/login 응답(R02, 데몬 #353). 아직 쿠키 없음. approval 바이트를 같은 개인키로 서명해 key/approve로 보낸다 */
export interface DKeyLoginReply {
  approve: true;
  ticketId: string;
  sessionDigest: string;
  approval: string;
  deadline: string;
}
export interface DKeyChallenge {
  ticketId: string;
  ticket: DTicket;
  ticketBytes: string;
  proof: string;
  deadline: string;
}
/** GET /me/credentials */
export interface DOwnCredentials extends DUserRecord {
  accountRevision: number;
}

export interface DMember {
  id: string;
  key: string;
  endpoint: string;
  joinID?: string;
  joinId?: string;
  /** 수명 주기 행 revision: 격리·복구·제거·신원 교체의 expected (행이 없으면 가입 항목 것) */
  revision: number;
  /** 가입 항목 revision: promote의 expected (데몬 #380) */
  joinRevision?: number;
  phase: 'active' | 'isolated' | 'pending' | 'removed';
  voter: boolean;
  /** 가입 중이면 없다 */
  admitsWork?: boolean;
  /** 새 배치 제외 */
  cordoned?: boolean;
  /** 막은 사유. 데몬이 mydcd에 싣는 중이라 아직 없을 수 있다 */
  cordonReason?: string;
  /** 막은 사람·시각 */
  cordonedBy?: string;
  cordonedAt?: string;
  /** 새 배치 막기 행. revision이 막기·풀기의 expected. 가입 중이면 없다 */
  scheduling?: { cordonedBy?: string; cordonedAt?: string; enabled: boolean; revision: number };
  /** 비우기 진행 */
  drain?: DNodeDrainProgress;
  /** 마지막 신원 교체 시각. 데몬이 mydcd에 싣는 중이라 아직 없을 수 있다 */
  identityRotatedAt?: string;
  /** 마지막 신원 교체. phase: Preparing → Prepared → Activated → Installed */
  identity?: { operation: string; phase: string; failure?: string };
  pendingOperation?: string;
  /** 가입 단계(UI-13): invited → learner → ready → promoting → active */
  join?: 'invited' | 'learner' | 'ready' | 'promoting' | 'active' | string;
}
/** GET /nodes/{node}/invitation/summary */
export interface DInvitationSummary {
  node: string;
  cluster: string;
  joinId: string;
  approvalRevision: number;
  source: { id: string; key: string; endpoint: string };
  target: { id: string; key: string; endpoint: string };
}
/** GET /nodes/{node}/image-prune-plan (데몬 #384). images는 한 번에 지울 미사용 이미지 최대 8개 */
export interface DNodeImagePrunePlan {
  node: string;
  /** ref는 첫 별칭(없으면 빈 값), digest는 전체 이미지 ID */
  images: { ref: string; aliases?: string[] | null; digest: string; bytes: number }[] | null;
  /** Docker가 알린 크기의 합. 실제 회수량이 아니다 */
  bytes: number;
  plan: string;
  /** 이번에 못 넣어 다음 정리로 넘어가는 미사용 이미지 수 */
  remaining?: number;
  /** 쓰는 중이라 남기는 이미지 수 */
  inUse?: number;
  total?: number;
}
/** GET /image-prunes/op-<opId>: 정리 진행. op applied는 접수일 뿐이다 */
export interface DImagePrune {
  operation: string;
  user?: string;
  state: 'queued' | 'running' | 'done' | 'failed' | string;
  node: string;
  at?: number;
  revision?: number;
  images: string[] | null;
  parts: { digest: string; state: 'removed' | 'already-absent' | 'failed' | 'skipped' | string; code?: string; error?: string; at?: number }[] | null;
}
/** GET /t/{t}/networks/{name}/tunnels (RQ4, 데몬 #307). 다시 연결 횟수는 없다 */
export interface DTunnelLink {
  tenant: string;
  network: string;
  /** 정렬한 a/b */
  pairId: string;
  from: string;
  to: string;
  state: 'up' | 'degraded' | 'down' | 'pending' | string;
  /** Unix 초 */
  since: number;
}
/** GET /tunnel-reconnects/{operation}. op applied는 접수일 뿐이고 결과는 여기서 본다 */
export interface DTunnelReconnect {
  operation: string;
  user?: string;
  state: 'queued' | 'running' | 'done' | 'failed';
  node: string;
  peer: string;
  pairId: string;
  at: number;
  revision: number;
  result?: 'reconnected' | 'already-connected' | 'failed' | string;
  code?: string;
  error?: string;
  /** Unix ms */
  handshakeAt?: number;
  keptExisting?: boolean;
}
export interface DMembersPage extends ListPage<DMember> {
  voters: number;
  quorum: number;
  runtimeRevision: number;
  operationEpoch: number;
  configurationIndex: number;
  /** 원장 세대(mydcd ModuleEpoch, 없으면 1)와 그 기록 revision. 데몬 계약 요청 중 */
  ledgerEpoch?: number;
  ledgerRevision?: number;
}

/** GET /nodes/summary 행 (데몬 #373). status는 화면 말(unready→degraded, 나머지는 state 그대로라 pending·draining·removed 같은 서버 단계도 온다).
 *  role·cpuPercent·총량은 클러스터 전체 보기에서만, 작업 공간 보기는 containers(와 mydcd가 주면 memUsed)만 */
export interface DNodeSummary {
  node: string;
  status: 'ready' | 'degraded' | 'unreachable' | 'isolated' | 'pending' | 'draining' | 'removed' | string;
  /** mydcd 값(ready/unready/unreachable/pending/서버 단계) */
  state?: string;
  ready?: boolean;
  stale?: boolean;
  /** mydcd 값(leader/candidate/voter/non-voter/pending). 클러스터 전체 보기에서만 */
  role?: 'leader' | 'candidate' | 'voter' | 'non-voter' | 'pending' | string;
  /** 새 배치 제외(cordon) 상태 */
  scheduling?: { cordonedBy?: string; cordonedAt?: string; enabled: boolean; revision: number };
  cordonedBy?: string;
  cordonedAt?: string;
  /** unreachable 기준 */
  observeLimitSeconds?: number;
  cpuPercent?: number;
  memUsed?: number;
  memTotal?: number;
  diskUsed?: number;
  diskTotal?: number;
  containers: number;
  observedAt: number;
}

export interface DStorageRoot {
  node: string;
  id: string;
  path: string;
  tenants: string[];
  generation: number;
  revision: number;
  draining: boolean;
  /** 웹 계약 보강 요청 중(데몬 스레드). 없으면 화면이 모름으로 다룬다. */
  maxVolumes?: number;
  closed?: boolean;
  attested?: boolean;
  volumes?: number;
}

/** GET /t/{t}/storage 행 (REQ-30·58, #222) */
export interface DTenantStorageRoot {
  node: string;
  id: string;
  generation: number;
  revision: number;
  draining: boolean;
  allowed: boolean;
  root: { cluster: string; node: string; key: string; id: string; generation: number; path: string };
  volumes?: number;
}

export interface DNodeDisk {
  node: string;
  mount: string;
  device: string;
  fsType: string;
  purpose: 'system' | 'container-runtime' | 'storage-root' | string;
  storageRootID?: string;
  /** 데몬 #365: 행 id, 관측 상태, 용도·저장 경로 전부, 오래된 관측 */
  id?: string;
  state?: 'observed' | 'unknown' | string;
  purposes?: string[] | null;
  storageRoots?: string[] | null;
  /** 관측 전이면 없다 */
  total?: number;
  used?: number;
  free?: number;
  available?: number;
  inodesFree?: number;
  observedAt: number;
  stale?: boolean;
}

export interface DMeshLink {
  nodeA: string;
  nodeB: string;
  state: 'up' | 'degraded' | 'down' | 'pending';
  id?: string;
  /** 클러스터 전체 보기에서만 온다 */
  rttMillis?: number;
  lossPercent?: number;
  stale?: boolean;
  lastHandshakeAt?: number;
  lastChangeAt?: number;
  observedBy?: string;
  observedAt: number;
}

/** GET /raft (데몬 #367). 서버가 알리지 않은 숫자는 빠진다. 시간은 Unix 초 */
export interface DRaftServer {
  node: string;
  suffrage: 'voter' | 'non-voter';
  role?: 'leader' | 'follower' | 'candidate' | 'non-voter' | 'pending' | string;
  matchIndex?: number;
  appliedIndex?: number;
  lag?: number;
  snapshotIndex?: number;
  logEntries?: number;
  logBytes?: number;
  lastContactAt?: number;
  stale?: boolean;
}
export interface DRaftStatus {
  leader: string;
  observedBy?: string;
  term: number;
  commitIndex: number;
  appliedIndex?: number;
  configurationIndex: number;
  voters?: number;
  quorum?: number;
  respondingVoters?: number;
  stale: boolean;
  servers: DRaftServer[] | null;
  lastSnapshotIndex?: number;
  lastSnapshotAt?: number;
  elections: { term: number; leader: string; at: number; reason: string }[] | null;
  electionsDropped?: number;
  observedAt?: number;
}

export interface DCredential {
  id: string;
  method: 'password' | 'token' | 'private-key' | string;
  publicKey?: string; // hex
  verifierRef?: string;
  enabled: boolean;
}
export interface DUserRecord {
  id: string;
  username: string;
  revision: number;
  enabled: boolean;
  systemAdmin: boolean;
  credentials: DCredential[] | null;
  accountRevision?: number;
}

export interface DTenantMember {
  tenant: string;
  user: string;
  username: string;
  role: 'manager' | 'viewer';
  revision: number;
  enabled: boolean;
}

export interface DTenantRetirement {
  tenant: string;
  retiring: boolean;
  index: number;
  rootRevision: number;
  targetCount: number;
  ownerCount: number;
  closedOwners: number;
  remainingCount: number;
  remaining: string[] | null;
  next?: string;
  /** 진행 중인 종료 작업 식별자(종료 중이 아니면 ""). */
  operation?: string;
  /** 작업 공간 revision · 종료 시작·마치기의 expected. */
  revision?: number;
  /** active · retiring · deleted */
  phase?: string;
  /** 모든 소유자 보고가 끝나 마칠 수 있음. */
  ready?: boolean;
}

export interface DResourceEntry {
  key: string;
  tenant: string;
  network?: { name: string; kind: 'bridge' | 'tun'; cidr: string; nodes: string[] | null; revision: number; dns?: { zone: string; enabled: boolean; revision: number; upstreams?: string[] | null; ttl?: number; negativeTtl?: number; reverse?: boolean; resolver?: string }; members?: DNetworkMember[] | null; apps?: number; standalones?: number };
  route?: { host: string; path: string; app: string; service: string; port: number; revision: number };
  limit?: { node: string; cpus: number; memoryBytes: number; maxContainers: number; revision: number; nodeCpus?: number; nodeMemoryBytes?: number };
}

export interface DOperationSummary {
  failed?: boolean;
  id: string;
  status: string;
  plan?: string;
  completedAt?: number;
  submitter?: string;
  epoch?: number;
}

export interface DAppView {
  tenant: string;
  app: string;
  deployment: string;
  revision: number;
  operation: DOperationSummary;
  claims: number;
  health?: 'healthy' | 'degraded' | 'unhealthy' | 'unknown' | '';
  observedAt?: number;
  retiring?: boolean;
  cd?: { revision: number; repository: string; branch: string; mode: string; paused: boolean; running?: string; candidate?: string; candidateDigest?: string; sourceError?: string };
}

export interface DDashboard {
  nodes: DNodeSummary[];
  apps: DAppView[];
  appsNext?: string;
  asOf: string;
}

export interface DTask {
  tenant: string;
  app: string;
  service: string;
  instance: string;
  node: string;
  image: string;
  generation: number;
  desired: 'running' | 'stopped';
  observed: 'running' | 'exited' | 'restarting' | 'created' | 'missing';
  health: 'healthy' | 'unhealthy' | 'starting' | 'none';
  restarts: number;
  exitCode?: number;
  startedAt?: number;
  observedAt: number;
  lastCheck?: string;
}

export interface DAppSource {
  tenant: string;
  app: string;
  version: number;
  yaml: string;
  digest: string;
  submitter: string;
  operation: string;
  acceptedAt?: string;
}

export interface DAppRevision {
  version: number;
  digest: string;
  submitter: string;
  operation: string;
  status: string;
  acceptedAt: number;
}

export interface DAppPlan {
  digest: string;
  length: number;
  data?: string;
  app: string;
  services: { name: string; image: string; node: string; change: 'add' | 'update' | 'remove' | 'keep' }[] | null;
  diff?: string;
}

export interface DArchived {
  key: string;
  tenant: string;
  app: string;
  digest: string;
  version: number;
  volumes: string[] | null;
  downBy: string;
  downAt: string;
  downOp: string;
  yaml?: string;
}

export interface DUpload {
  id: string;
  app: string;
  deployment: string;
  revision: number;
  length: number;
  digest: string;
  missing: number[] | null;
}

export interface DVolume {
  key: string;
  tenant: string;
  name: string;
  kind: 'shared' | 'fixed';
  node?: string;
  storage?: string;
  app?: string;
  revision: number;
  consumers: number;
  capacityBytes?: number;
  /** 소유 서버의 주기 측정(데몬 #370). 30분 안 측정이 없으면 빠진다 = 모름(0 아님) */
  usedBytes?: number;
  /** usedBytes를 잰 때. Unix 밀리초 */
  usageObservedAt?: number;
  retain: boolean;
  phase?: string;
  moveID?: string;
  targetNode?: string;
  movePhase?: string;
  /** 끝난 옮기기가 원래 서버에 남긴 원본(REQ-43 mock. 실제 mydcd 행에는 아직 없다) */
  retained?: DVolumeRetained[] | null;
  /** 쓰기로 붙인 앱 서비스(app/service) */
  writer?: string;
}

/** 데이터 저장소 백업 행. phase: Reserved → Ready/Failed, Cancelling → Cancelled, Deleting → Deleted */
export interface DVolumeBackup {
  key: string;
  tenant: string;
  volume: string;
  id: string;
  node: string;
  phase: string;
  revision: number;
  bytes: number;
  /** 데몬은 유닉스 초(int64). 화면용으로는 endpoints가 ISO 문자열로 바꾼다 */
  createdAt: number | string;
  failure?: string;
}
/** 복원 행. phase: Reserved/Cancelling/Restored/Cancelled */
export interface DVolumeRestore {
  key: string;
  tenant: string;
  volume: string;
  backup: string;
  id: string;
  node: string;
  phase: string;
  target: string;
  revision: number;
  maxBytes: number;
  capacityBytes?: number;
}
export interface DVolumeRetained {
  moveID: string;
  node: string;
  state: 'retained' | 'deleting' | 'removed';
}
/** POST /t/{t}/volumes/{name}/move-plan. 바꾸지 않는다 */
export interface DVolumeMovePlan {
  volume: string;
  app: string;
  id: string;
  from: string;
  to: string;
  yaml: string;
  digest: string;
  capacityBytes: number;
  maxBytes: number;
  maxEntries: number;
  transferSeconds: number;
  expiresAt: string;
  cd: boolean;
  services: { name: string; image: string; node: string; change: string }[] | null;
}
export interface DVolumeDetail {
  volume: DVolume;
  backups: DVolumeBackup[] | null;
  restores: DVolumeRestore[] | null;
}

/** 작업 공간 간 연결(tenancy.Route). docs/reference/web-api.md "작업 공간 간 연결 (UI-53)" */
export interface DRouteEnd {
  tenant: string;
  /** mydcd의 멤버 망 ID */
  network: string;
  node: string;
  cidr?: string;
  /** 망 이름. 이 작업 공간 쪽에만 붙는다 */
  name?: string;
}
export interface DRoute {
  key: string;
  id: string;
  sourceTenant: string;
  source: DRouteEnd;
  destination: DRouteEnd;
  protocol: 'tcp' | 'udp';
  ports: { first: number; last: number }[] | null;
  phase: 'pending' | 'active' | 'revoking';
  approvals: { tenant: string; user?: string }[] | null;
  generation?: number;
  revision: number;
  side: 'source' | 'destination';
  /** active / waiting-me(이 작업 공간 승인 전) / waiting-peer / revoking */
  state: 'active' | 'waiting-me' | 'waiting-peer' | 'revoking';
}
export interface DRoutesPage {
  items: DRoute[] | null;
  next?: string;
  networksRevision: number;
}

export interface DVault {
  realm: string;
  path: string;
  kind: 'object' | 'group';
  profile: string;
  keys: string[] | null;
  revision: number;
  group?: string;
  /** 비밀번호가 걸린 묶음 */
  protected?: boolean;
  /** mydcd 객체 ID와 부모(뿌리 묶음 ID는 작업 공간 이름). 이전 데몬은 없음 */
  id?: string;
  parent?: string;
  status?: DVaultStatus;
  acl?: DVaultACL;
  pendingWrite?: string;
  /** 묶음 승인 유효 기간(초, 0이나 없음 = 제한 없음) */
  maxApprovalAge?: number;
}
/** GET …/vault/usages 항목 */
export interface DVaultUsage {
  /** 데몬 #298: mydcd vault-usages 행 */
  id?: string;
  tenant?: string;
  user?: string;
  app?: string;
  deployment?: string;
  service?: string;
  standalone?: string;
  node: string;
  purpose?: string;
  generation?: number;
  secrets: string[] | null;
  /** 살아 있는 사용(폐기를 막음) */
  live: boolean;
}
export type DVaultStatus = 'active' | 'password-pending' | 'revoking' | 'retired' | 'reference-pending';
/** 이름 목록. 허용이 비면 작업 공간 안에서 제한 없음, 거부가 앞선다 */
export interface DVaultACL {
  users: string[] | null;
  services: string[] | null;
  denyUsers: string[] | null;
  denyServices: string[] | null;
  tenantGrants?: string[] | null;
}

/** 상태 검사 스크립트 한 버전 */
export interface DLifecycleVersion {
  revision: number;
  active: boolean;
  deleted: boolean;
  /** 원본 sha256 hex */
  digest: string;
  length: number;
  modules: { path: string; version: string }[] | null;
}
/** 상태 검사 스크립트(이름 하나, 버전 묶음). GET /t/{t}/lifecycle-scripts 의 L */
export interface DLifecycle {
  name: string;
  recordRevision: number;
  /** 0 = 활성 버전 없음 */
  activeRevision: number;
  latestRevision: number;
  versions: DLifecycleVersion[] | null;
}
export interface DLifecycleScripts {
  items: DLifecycle[] | null;
  policy: { configured: boolean; enabled: boolean; revision: number };
}
export interface DLifecycleUse {
  /** 데몬 #298: mydcd lifecycle-uses 행 ID */
  id?: string;
  revision: number;
  /** app-binding · build-job */
  kind: string;
  app?: string;
  standalone?: string;
  service?: string;
  node?: string;
}
/** GET /t/{t}/lifecycles/{name}?revision= */
export interface DLifecycleDetail {
  script: DLifecycle;
  revision: number;
  /** 그 버전 원본 글. 읽을 수 없으면 null */
  source: string | null;
  sourceAvailable: boolean;
  usedBy: DLifecycleUse[] | null;
  usedByAvailable: boolean;
}
/** 상태 검사 정책(UI-91, set-lifecycle-policy 전체) */
export interface DLifecyclePolicy {
  tenant: string;
  revision: number;
  enabled: boolean;
  build: { nodes: string[] | null; targets: string[] | null; image: string; toolchain: string; maxJobs: number; nanoCPU: number; memoryBytes: number; workspaceBytes: number; artifactBytes: number; timeoutMS: number };
  execution: { maxConcurrent: number; timeoutMS: number; nanoCPU: number; memoryBytes: number; maxPIDs: number; outputBytes: number; probeBytes: number; capabilities: string[] | null };
  resolver: { allowPackages: string[] | null; denyPackages: string[] | null; modules: { path: string; version: string; digest: string; length: number }[] | null; sourceCacheBytes: number };
  compiledCacheBytes: number;
}

export interface DRegistryLimits {
  metadata: { manifestBytes: number; records: number; totalBytes: number };
  blobs: { blobBytes: number; totalBytes: number; records: number };
  /** cpu: 1e9 = 1코어 */
  budget: { cpu: number; memory: number };
  maxRequests: number;
  maxHeaderBytes: number;
  requestTimeoutMS: number;
  tokenSeconds: number;
}
export type RegistryStatus = 'serving' | 'pending' | 'draining' | 'stopping' | 'stopped' | 'deleted';
export interface DRegistry {
  tenant: string;
  id: string;
  name: string;
  /** TLS authority (host[:port]) */
  endpoint: string;
  revision: number;
  generation: number;
  active: boolean;
  repositories: number;
  // 내장 저장소 정의(UI-80, web-api.md '내장 저장소'). 옛 데몬에는 없다.
  node?: string;
  address?: string;
  /** 노드가 지금 쓴다고 보고한 보관함 인증서 ID(64자 hex). 보고 전에는 없음 */
  certificateID?: string;
  volume?: string;
  enabled?: boolean;
  deleted?: boolean;
  draining?: boolean;
  /** Unix ms. 0/없음 = 보고 없음 */
  observedAt?: number;
  status?: RegistryStatus;
  limits?: DRegistryLimits;
  /** 정리 작업 요약(#242) */
  maintenance?: DRegistryMaintenance;
}
/** GET /t/{t}/image-trust */
export interface DTrustUse {
  app?: string;
  deployment?: string;
  service?: string;
  standalone?: string;
  image: string;
  rules: number[] | null;
}
export interface DTrustRule {
  index: number;
  registry: string;
  repository: string;
  origin: 'default' | 'builtin' | 'direct' | 'external' | string;
  pull: 'registry-credential' | 'anonymous' | string;
  uses: DTrustUse[] | null;
  only: number;
}
export interface DImageTrust {
  tenant: string;
  revision: number;
  rules: DTrustRule[] | null;
  uses: DTrustUse[] | null;
  untrusted: DTrustUse[] | null;
}

export interface DOp {
  id: string;
  requestId?: string;
  action: string;
  tenant?: string;
  target?: string;
  state: 'applied' | 'failed' | 'rejected' | 'unknown' | 'pending' | 'running';
  errorCode?: string;
  resultFound?: boolean;
  resultCode?: number;
  index?: number;
  revision?: number;
  submittedAt: string;
  updatedAt: string;
  /** 배포 묶음의 단계 행이면 묶음 opId */
  parent?: string;
  /** 배포 묶음: 다음 단계 / 전체 단계 */
  step?: number;
  steps?: number;
  /** 배포 묶음: 비밀번호로 보호된 묶음 승인(errorCode approval-required일 때 기다림) */
  approvals?: DGroupApproval[] | null;
}
export interface DGroupApproval {
  realm: string;
  group: string;
  services: string[] | null;
  state: 'required' | 'approved' | 'unknown';
}
/** GET /t/{t}/vault/approvals: 내 배포가 기다리는 묶음 승인 */
export interface DPendingApproval extends DGroupApproval {
  opId: string;
  /** deploy(앱 배포), build(빌드 비밀값, #226), registry-bind(외부 저장소 서버 연결, #232), standalone(단독 컨테이너 실행, #291). 없으면 deploy */
  kind?: 'deploy' | 'build' | 'registry-bind' | 'standalone' | string;
  app?: string;
  /** standalone 행: 단독 컨테이너 이름(app 대신) */
  standalone?: string;
  /** build 행: 빌드 컨텍스트와 빌드 ID */
  context?: string;
  build?: string;
  /** registry-bind 행: 외부 저장소 정의 ID와 연결할 서버 */
  source?: string;
  node?: string;
  updatedAt: string;
}
/** GET /t/{t}/vault/approvals/granted 항목. 시각은 Unix 초 */
export interface DGrantedApproval {
  id: string;
  realm: string;
  group: string;
  tenant?: string;
  user: string;
  app?: string;
  standalone?: string;
  deployment?: string;
  purpose?: string;
  services: string[] | null;
  nodes: string[] | null;
  approvedAt: number;
  expiresAt?: number;
  issuer: string;
  /** 데몬 #298: 철회가 받아들여져 쓰는 곳을 돌려받는 중. 철회가 끝난 것은 목록에서 빠진다 */
  revoking: boolean;
  consumers?: number;
}

/** POST /ops 본문. payload 키는 mydcd Go 필드 이름(대소문자 무시 매칭). */
export interface OpRequest {
  opId: string;
  action: string;
  principal: string;
  expected: number;
  payload?: unknown;
  rootRevision: number;
  tenant?: string;
  target?: string;
}

/** GET /notifications 행(웹 bbolt, 사용자별 사본) */
export interface DNotification {
  id: string;
  kind: string;
  severity: 'info' | 'warning' | 'error' | string;
  tenant?: string;
  title: string;
  body?: string;
  link?: string;
  action: boolean;
  createdAt: string;
  readAt?: string;
}
export interface DNotifyPrefs {
  mutedKinds: string[] | null;
  mutedTenants: string[] | null;
  browser: boolean;
}

export interface DWebSettings {
  sessionMaxHours: number;
  sessionIdleMinutes: number;
  opRetentionDays: number;
  auditRetentionDays: number;
  notificationRetentionDays: number;
  /** 아래는 웹 데몬 계약 요청 중(없으면 웹 기능 준비 중) */
  allowKeyLogin?: boolean;
  maxSessionsPerUser?: number;
  webhookDeliveryRetentionDays?: number;
  mcpCallRetentionDays?: number;
}
export interface DSealStatus {
  state: 'ready' | 'no-key' | 'wrong-key' | 'broken' | string;
  ready: boolean;
  reason?: string;
  kinds?: { kind: string; count: number; modified?: string }[] | null;
  /** 아래는 웹 데몬 계약 요청 중 */
  keySource?: 'env' | 'file' | string;
  fingerprint?: string;
  dir?: string;
  files?: number;
  next?: { fingerprint: string };
}
export interface DSettingsReply {
  settings: DWebSettings;
  defaults: DWebSettings;
  info: { version: string; schema: number; dbBytes: number; restorePending: boolean; dbPath?: string; /** mydcd 소켓 경로(늘 있음) */ socket: string; connected?: boolean; mydcdVersion?: { version: string; commit?: string; /** RFC 3339 */ buildTime?: string; /** MYDCP 번호 문자열("1") */ protocol: string }; container?: { tenant: string; app: string; service: string; instance: string; node: string } };
  seal: DSealStatus;
}
export interface DAudit {
  id: string;
  at: string;
  user: string;
  username: string;
  tenant?: string;
  area: string;
  action: string;
  target?: string;
  before?: unknown;
  after?: unknown;
}

// ── 단독 컨테이너 (REQ-29, UI-3E·3F) ──
export interface DStandalone {
  name: string;
  lifetime: 'temp' | 'fixed';
  mode: 'shell' | 'entrypoint';
  image: string;
  node: string;
  /** removed: 끝난 임시(지운 뒤 1시간 기록만) */
  state: 'running' | 'exited' | 'restarting' | 'created' | 'missing' | 'pending' | 'removed';
  exitCode?: number;
  restarts: number;
  restartPolicy?: 'no' | 'on-failure' | 'always';
  /** 임시만. Unix 초 */
  expiresAt?: number;
  graceSeconds?: number;
  disconnectedAt?: number;
  endedAt?: number;
  /** 이미지 digest(있으면) */
  digest?: string;
  connections: number;
  owner: string;
  ownerName?: string;
  revision: number;
  generation?: number;
  yaml: string;
  createdAt: number;
  observedAt?: number;
  /** 마지막으로 만들거나 바꾼 작업 ID */
  operation?: string;
  /** 앱 서비스 설정을 가져와 만들었을 때 그 출처(웹 서버가 bbolt에 보관, applied된 up에서만). CLI로 만든 것은 없음 */
  importedFrom?: { app: string; deployment?: string; service: string; items: string[]; by: string; at: number };
}
export interface DStandalonePlan {
  name: string;
  digest?: string;
  /** 같은 이름이 이미 있으면 그 revision(바꾸기), 없으면 0 */
  revision: number;
  create: boolean;
  recreate: boolean;
  changes: { field: string; before?: unknown; after?: unknown }[] | null;
  impact: { kind: string; target: string; detail: string; code?: string; blocking: boolean }[] | null;
  /** 한도(#291: 서버당 node/nodeMax 추가). mydcd가 주지 않으면 없다 */
  limits?: { mine: number; mineMax: number; tenant: number; tenantMax: number; node?: number; nodeMax?: number };
  /** mydcd 내부 이름 */
  scope?: string;
  services?: string[];
  /** 웹 목업만: 바꾸기일 때 줄 차이 */
  diff?: string;
}

/** 망 멤버(서버 하나의 tenancy.Network 행)와 그 변경. */
export interface DNetworkChangeRef {
  id: string;
  generation: number;
  revision: number;
  targetRevision: number;
  /** reserved · draining · fenced · committed · cancelled */
  phase: string;
  targetCidr: string;
  metadataOnly?: boolean;
}
export interface DNetworkMember {
  node: string;
  id: string;
  cidr: string;
  tunnel?: string;
  generation: number;
  revision: number;
  draining: boolean;
  change?: DNetworkChangeRef;
  /** 망 안 이름 확인 주소(DNS가 켜져 있을 때만) */
  resolver?: string;
}
/** GET /t/{t}/networks/{name}/change */
export interface DNetworkChange {
  name: string;
  kind: 'bridge' | 'tun';
  networksRevision: number;
  dnsEnabled: boolean;
  members: { node: string; id: string; cidr: string; tunnel?: string; revision: number; draining: boolean; phase: 'none' | 'reserved' | 'draining' | 'fenced'; target: string; change?: DNetworkChangeRef }[];
  next: '' | 'drain' | 'fence' | 'commit';
  /** 비운(draining) 멤버마다 하나. 서버가 서명한 정리 보고(network-closure) */
  closure: DNetworkClosure[];
}
export interface DNetworkClosure {
  node: string;
  /** 데몬 #298 */
  state?: 'pending' | 'unreachable' | 'closed';
  closed: boolean;
  unreachable: boolean;
  /** mydcd가 재지 않았으면 null */
  nativeGone?: boolean | null;
  pendingEndpoints: number | null;
  pendingFlows: number | null;
  pendingPins: number | null;
}
/** 망·저장소를 쓰는 곳 하나(GET …/networks/{name}/users, …/volumes/{name}/users) */
export interface DResourceUser {
  /** service · standalone · volume-operation(백업·옮기기가 읽는 중) */
  kind: string;
  /** volume-operation이면 그 작업 ID */
  consumer?: string;
  app?: string;
  service?: string;
  /** 단독 컨테이너 이름 */
  standalone?: string;
  node?: string;
  readOnly?: boolean;
  attached?: boolean;
  selection?: { app?: string; service?: string; instance?: string }[];
}
export interface DResourceUsers {
  users: DResourceUser[];
  apps?: number;
  standalones?: number;
  /** 묶은 행 수(#288). 관측 시각은 mydcd가 주지 않아 없다 */
  total?: number;
}
/** GET /t/{t}/backup-limits?node= 의 행 하나 */
export interface DBackupLimit {
  node: string;
  scope: 'workspace' | 'server';
  hidden?: boolean;
  count: number;
  bytes: number;
  stagingCount: number;
  stagingBytes: number;
  revision: number;
  used: { count: number; bytes: number; stagingCount: number; stagingBytes: number };
}

/** 자동 배포 정책(cd.policy). 읽은 그대로 고쳐 PUT /cd/policy로 보낸다 */
export interface DCdPolicy {
  enabled: boolean;
  source: { kind: string; repository: string; ref: string; path: string; credential: string };
  poll: number;
  sync: { mode: string; drift: string; prune: boolean; allowEmpty: boolean };
  runtime: { mode: string; expiry: string };
  limits: { fetch: number; bytes: number; queued: number; active: number };
}
/** GET /t/{t}/apps/{app}/cd 의 cd */
export interface DCdState {
  revision: number;
  repository: string;
  branch: string;
  mode: string;
  paused: boolean;
  running?: string;
  candidate?: string;
  candidateDigest?: string;
  sync?: string;
  effectiveSync?: string;
  operation?: string;
  health?: string;
  source?: string;
  sourceError?: string;
  blocked?: string;
  transition?: string;
  transitionPhase?: string;
  lastSuccessCommit?: string;
  activeOperation?: string;
  changeCount?: number;
  policyRevision: number;
  policy?: DCdPolicy;
  principal?: string;
  overrideRevision: number;
  overrideCount?: number;
  overridePaths?: string[][] | null;
  /** 배포 전 확인 웹훅 상태 (cd-webhooks-contract.md, 웹 데몬) */
  webhook?: CdGate;
  /** 종류마다 가장 최근 확인 */
  checks?: { 'pre-sync'?: CdGate; 'post-sync'?: CdGate };
}
/** GET …/cd/history 행 */
export interface DCdHistory {
  commit: string;
  candidateDigest: string;
  /** Unix 초 */
  plannedAt: number;
  result: 'candidate' | 'running' | 'succeeded' | 'failed' | 'abandoned' | 'blocked' | string;
  reason?: string;
  operation?: string;
  finishedAt?: number;
  /** 이 후보의 웹훅 확인 (데몬 #168). 확인이 없던 후보는 없음 */
  checks?: { 'pre-sync'?: CdGate; 'post-sync'?: CdGate };
}
/** GET …/cd/values */
export interface DCdValues {
  tenant: string;
  app: string;
  path: string[];
  running?: string;
  candidate?: string;
  gitRunning?: unknown;
  gitCandidate?: unknown;
  current?: unknown;
  overridden: boolean;
  secrets?: unknown;
}
/** GET …/cd/local: 웹이 더한 서비스(services:만 있는 app.yaml 조각) */
export interface DCdLocal {
  tenant: string;
  app: string;
  /** CD revision: 바꾸기(PUT)의 expected */
  revision: number;
  /** 로컬 부분의 revision (0 = 아직 없음) */
  localRevision?: number;
  /** 마지막으로 바꾼 사람 */
  actor?: string;
  /** 다음 sync를 기다리는 웹 추가분 */
  document: string;
  services: string[];
  gitServices: string[];
  conflicts?: string[] | null;
}
/** GET …/cd/changes */
export interface DCdChanges {
  tenant: string;
  app: string;
  running: string;
  candidate: string;
  services: { service: string; fields: { path: string[]; before?: unknown; after?: unknown }[] | null }[] | null;
  added: string[] | null;
  removed: string[] | null;
  count: number;
}
export interface DCdField {
  target: string;
  revision: number;
  path: string[];
  override?: { revision: number; actor: string; anchors: unknown };
}

/** 저장소 이미지와 정리 (UI-84·8A, mydcd 실제 계약 #242). docs/reference/web-api.md '저장소 이미지와 정리' */
export interface DCatalogRow {
  repository: string;
  /** 태그 또는 digest 자체 */
  reference: string;
  digest: string;
  mediaType: string;
  manifestBytes: number;
  imageBytes: number;
  /** RFC 3339. mydcd가 알 때만(외부 저장소는 없음) */
  uploadedAt?: string;
}
export interface DCatalogPage {
  kind: 'managed' | 'external';
  id: string;
  authority: string;
  repository?: string;
  /** 있으면 목록을 못 읽은 까닭(unauthorized, denied, not-found, unsupported, unavailable …) */
  code?: string;
  live: boolean;
  untaggedComplete: boolean;
  repositories: string[] | null;
  items: DCatalogRow[] | null;
  next: string;
  asOf: string;
  cachedAt: string;
}
/** 내장 저장소 행의 maintenance (Unix 밀리초) */
export interface DRegistryMaintenance {
  pendingOperation?: string;
  pendingState?: string;
  lastGCOperation?: string;
  lastGCAt?: number;
  reclaimedBytes: number;
}
export interface DArchivedUse {
  key: string;
  app: string;
  image: string;
  downAt?: string;
}
export interface DUsageRow {
  id: string;
  app?: string;
  deployment?: string;
  node?: string;
  service?: string;
  instance?: string;
  image?: string;
  /** app-execution, cd-candidate, app-previous … */
  kind: string;
  task?: string;
  operation?: string;
  version?: number;
  unknown?: boolean;
  /** exact, digest, repository-unknown, unknown, scope */
  match: string;
}
export interface DImageUse {
  ref: string;
  rows: DUsageRow[] | null;
  truncated: boolean;
  archived: DArchivedUse[] | null;
}
export type MaintenanceState = 'queued' | 'running' | 'done' | 'failed' | 'unknown';
export interface DMaintenanceResult {
  code: string;
  at: string;
  reclaimedBytes: number;
  native?: string;
  prune?: { processed: number; deleted: number; skipped: number; failed: number; gcCode?: string; gcAt?: string };
}
export interface DMaintenanceStatus {
  operation: string;
  action: string;
  user: string;
  state: MaintenanceState;
  revision: number;
  at: string;
  registry: string;
  external: boolean;
  repository?: string;
  reference?: string;
  digest?: string;
  result?: DMaintenanceResult;
}
export interface DPruneConditions {
  repositories?: string[] | null;
  keepRecentPerRepository: number;
  /** Unix 초. 이보다 늦게 올린 것은 남김 */
  before?: number;
  excludeTags?: string[] | null;
  includeUntagged?: boolean;
  protectedDigests?: string[] | null;
  gc?: boolean;
}
export interface DPruneRow {
  id: string;
  image: DCatalogRow;
  aliases: number;
  aliasDigest: string;
  code?: string;
  at?: string;
}
export interface DPruneRetained {
  image: DCatalogRow;
  /** image-in-use, protected, excluded-tag, recent, upload-time-unknown, too-recent, untagged-excluded, manifest-dependency, repository-filter */
  code: string;
}
export interface DPrunePage {
  conditions: DPruneConditions;
  preview?: string;
  operation?: string;
  items: number;
  retained: number;
  imageBytes: number;
  estimatedReclaimedBytes: number;
  estimateKnown: boolean;
  live: boolean;
  expiresAt?: string;
  part: 'items' | 'retained';
  total: number;
  processed: number;
  rows: DPruneRow[] | null;
  retainedRows: DPruneRetained[] | null;
  next: string;
}

/** 외부 저장소 로그인. docs/reference/web-api.md '외부 이미지 저장소 로그인' */
export interface DRegistrySecretRef {
  realm: string;
  id: string;
  usernameKey: string;
  passwordKey: string;
}
export interface DRegistryCARef {
  realm: string;
  id: string;
  key: string;
}
/** 외부 저장소 정의(source) 행 (mydcd 실제 계약, #232). 시각은 Unix 초 */
export interface DExternalRegistry {
  id: string;
  authority: string;
  /** 정확한 경로, prefix/**, ** 중 하나 */
  repository: string;
  enabled: boolean;
  auth: 'none' | 'password' | 'token';
  credential?: DRegistrySecretRef;
  ca?: DRegistryCARef;
  revision: number;
  deleted: boolean;
  /** 이 정의로 실제로 읽는 서버. 없으면 로그인 시험을 못 한다 */
  reader?: { node: string; owner: string; generation: number; draining: boolean };
  pulls: { node: string; stage: string; code: string; completedAt: number; reportedAt: number; stale: boolean }[] | null;
}
export interface DExternalRegistryUse {
  app?: string;
  deployment?: string;
  node?: string;
  service?: string;
  instance?: string;
  image: string;
  /** mydcd 값(app-execution 등) */
  kind: string;
  match: string;
  unknown?: boolean;
}
export type LoginTestCode = 'ok' | 'unauthorized' | 'denied' | 'not-found' | 'unsupported' | 'unavailable' | 'timeout' | 'cancelled' | 'invalid-credential' | string;
export interface DLoginTest {
  id: string;
  generation: number;
  owner: string;
  /** Unix 초 */
  at: number;
  code: LoginTestCode;
  image?: { normalized: string; registry: string; repository: string; pinned: string; digest: string; mediaType: string; manifestBytes: number; platforms?: string[] | null };
  pull?: { manifestDigest: string; platform: string; blobs: number; compressedBytes: number };
}

// ── 이미지 빌드 (mydcd 실제 계약 PR #210, UI-85·86·87). 시각은 RFC 3339, 32바이트 값은 hex. 비밀값은 보관함 마운트뿐 ──
export interface DBuildPolicy {
  exists: boolean;
  revision: number;
  nodes: { node: string; root: { id: string; generation: number; path: string } }[] | null;
  concurrency: number;
  seconds: number;
  cpuMillis: number;
  memoryBytes: number;
  /** 입력 수락 예산(디스크 쓰기 강제 상한 아님) */
  workspaceBytes: number;
  /** 정리 목표(상한 아님) */
  cacheBytes: number;
  registry: string;
  platforms: string[] | null;
  builderImage: string;
  cleanup: { highWaterPercent: number; unusedDays: number };
  limits: { zipBytes: number; expandedBytes: number; fileReadBytes: number; logPageBytes: number };
}
export type BuildKind = 'upload' | 'git' | 'draft';
export interface DBuildSecret {
  id: string;
  realm: string;
  secret: string;
  key: string;
}
export interface DBuildGit {
  repository: string;
  ref: string;
  path?: string;
  credentialProfile?: string;
  automatic?: boolean;
}
export type BuildPhase = 'queued' | 'running' | 'unknown' | 'succeeded' | 'failed' | 'cancelled';
export type BuildCode = 'OK' | 'UNTRUSTED_BASE' | 'TIMEOUT' | 'SOURCE_FETCH' | 'BUILD_FAILED' | 'CANCELLED' | 'PERMISSION_REVOKED' | 'CONFLICT' | 'STORAGE_UNAVAILABLE';
export interface DBuild {
  id: string;
  context: string;
  node: string;
  user: string;
  phase: BuildPhase;
  /** 보존 버전 번호(지운 버전이면 0) */
  version: number;
  versionId: string;
  number: number;
  revision: number;
  createdAt?: string;
  closedAt?: string;
  cancel?: boolean;
  /** image는 성공 때 repo@sha256:… */
  result?: { code: BuildCode | string; image: string; bytes: number };
  automatic?: boolean;
}
export interface DBuildVersion {
  number: number;
  id: string;
  bytes: number;
  expandedBytes: number;
  entries: number;
  at?: string;
  commit?: string;
}
export interface DBuildContext {
  id: string;
  kind: BuildKind;
  revision: number;
  node: string;
  root: string;
  dockerfile: string;
  args?: Record<string, string> | null;
  secrets?: DBuildSecret[] | null;
  repository: string;
  tags: string[] | null;
  platforms?: string[] | null;
  git?: DBuildGit;
  gitCheck?: { code: string; commit?: string; at?: string; entries: number };
  /** 가장 새 보존 버전 번호, 0이면 없음 */
  version: number;
  versions: DBuildVersion[] | null;
  lastBuild?: DBuild;
}
export interface DBuildEntry {
  path: string;
  directory: boolean;
  executable: boolean;
  bytes: number;
  digest: string;
}
/** 초안(version 0, build-draft · PR #212). revision이 초안 편집의 expected */
export interface DBuildDraftTree {
  version: 0;
  revision: number;
  digest?: string;
  initialized: boolean;
  entries: DBuildEntry[] | null;
  /** Dockerfile 경로 */
  dockerfile: string;
}
/** 보존 버전 트리 */
export interface DBuildVersionTree {
  version: number;
  id: string;
  tree: string;
  entries: DBuildEntry[] | null;
  /** Dockerfile 경로(내용은 file 끝점) */
  dockerfile: string;
}
export type DBuildTree = DBuildDraftTree | DBuildVersionTree;
export interface DBuildVerify {
  context: string;
  code: 'OK' | 'SOURCE_FETCH' | 'UNTRUSTED_BASE' | 'INVALID_CONTEXT' | string;
  commit?: string;
  tree?: string;
  entries?: number;
  baseSources?: string[] | null;
  expandedBytes?: number;
}
export interface DBuildLog {
  text: string;
  offset: number;
  next: string;
  total: number;
  available: number;
  truncated: boolean;
  gap: boolean;
  unclosed: boolean;
  phase: BuildPhase;
  done: boolean;
}
/** BuildKit 기록 종류(regular, exec.cachemount, source.local, source.git.checkout, internal, frontend, other) */
export type BuildCacheKind = string;
export interface DBuildCacheCleanup {
  job: string;
  steps: { kind: string; selected: number; maxUsedSpace: number; sentAt?: string; returnedAt?: string; code?: string; removedCount: number; reportedBytes: number }[] | null;
}
export interface DBuildCacheUsage {
  recorded: boolean;
  available: boolean;
  borrowed?: boolean;
  observedAt?: string;
  lastAttemptAt?: string;
  lastAttemptCode?: string;
  /** '' = 빌드 끝 뒤 관측, 'cache-prune' = 정리 뒤 관측 (#218) */
  observedKind?: string;
  reportedBytes: number;
  count: number;
  kinds: { kind: BuildCacheKind; count: number; inUse: number; reportedBytes: number; sharedBytes: number }[] | null;
  /** 마지막 관측이 자동 정리였으면 있음 */
  cleanup?: DBuildCacheCleanup;
}
export interface DBuildCacheScope {
  cache: string;
  node: string;
  context: string;
  root: string;
  builder: string;
  job: string;
  contextDeleted?: boolean;
  code?: string;
  usage?: DBuildCacheUsage;
}
export interface DBuildCacheFilter {
  mode: 'all' | 'unused' | 'entries';
  ids?: string[] | null;
  unusedDays?: number;
}
export interface DBuildCleaning {
  id: string;
  node: string;
  context: string;
  cache: string;
  user: string;
  filter: DBuildCacheFilter;
  state: 'queued' | 'running' | 'unknown' | 'succeeded' | 'failed' | string;
  code?: string;
  acceptedAt?: string;
  closedAt?: string;
  removedCount?: number;
  reportedBytes?: number;
  automatic?: boolean;
}
export interface DBuildCache {
  cacheBytes: number;
  cleanup?: { highWaterPercent: number; unusedDays: number };
  nodes: { node: string; reportedBytes: number; entries: number; scopes: number }[] | null;
  caches: DBuildCacheScope[] | null;
  cleaning: DBuildCleaning[] | null;
}
export interface DBuildCacheEntry {
  id: string;
  kind: BuildCacheKind;
  bytes: number;
  createdAt?: string;
  lastUsedAt?: string;
  uses: number;
  inUse: boolean;
  mutable: boolean;
  shared: boolean;
}
/** 캐시 범위 하나의 항목 한 쪽(PR #212, 시각 RFC 3339) */
export interface DBuildCacheEntries {
  available: boolean;
  borrowed?: boolean;
  observedAt?: string;
  lastAttemptAt?: string;
  lastAttemptCode?: string;
  reportedBytes: number;
  count: number;
  offset: number;
  next?: string;
  entries: DBuildCacheEntry[] | null;
  cleanup?: DBuildCacheCleanup;
}

// ── 컨테이너 상세·이력·로그·표본, 옮기기 전 검사 ──

export interface DTaskSelection {
  app?: string;
  service?: string;
  instance?: string;
  standalone?: string;
}
export interface DTaskEnv {
  key: string;
  value?: string;
  /** secret:<object>/<key> — 값은 오지 않는다 */
  secret?: string;
}
export interface DTaskMount {
  kind: 'volume' | 'secret' | 'tmpfs' | string;
  source?: string;
  target: string;
  readOnly: boolean;
  mode?: string;
}
export interface DTaskNetwork {
  name: string;
  ip: string;
  aliases?: string[];
  dns?: string[];
}
export interface DTaskPort {
  port: number;
  protocol: string;
  ingress?: string;
  /** 서버 포트로 공개한 실제 바인딩(Docker inspect PortBindings, 서버가 고른 포트도 실제 값). 데몬 계약 요청 중 */
  published?: { hostIp?: string; hostPort: string }[];
}
export interface DTaskDetail {
  selection: DTaskSelection;
  node: string;
  name: string;
  /** 데몬은 nativeID로 보낸다(문서는 nativeId) */
  nativeID?: string;
  nativeId?: string;
  image: string;
  digest: string;
  command?: string[];
  entrypoint?: string[];
  workingDir?: string;
  user?: string;
  readOnly: boolean;
  capAdd?: string[];
  privileged: boolean;
  cpus?: number;
  memoryBytes?: number;
  logDriver: string;
  logOptions?: Record<string, string>;
  env: DTaskEnv[];
  mounts: DTaskMount[];
  networks: DTaskNetwork[];
  ports?: DTaskPort[];
  stopSignal: string;
  stopGrace: number;
  generation: number;
  drift?: string[];
  observedAt: number;
}
export type DTaskExitReason = 'exit' | 'oom' | 'health' | 'node-restart' | 'user' | 'log-clear';
export interface DTaskExit {
  at: number;
  reason: DTaskExitReason | string;
  exitCode: number;
  generation: number;
  nativeID?: string;
  nativeId?: string;
}
export interface DTaskCheckResult {
  at: number;
  ok: boolean;
  durationMs: number;
  message?: string;
}
export interface DTaskHistory {
  selection: DTaskSelection;
  exits: DTaskExit[];
  checks: { checker: string; consecutiveFailures: number; results: DTaskCheckResult[] }[];
}
export interface DTaskLogLine {
  seq: number;
  time: number;
  stream: 'stdout' | 'stderr' | string;
  text: string;
}
export interface DTaskLogPage {
  lines: DTaskLogLine[];
  cursor?: string;
  masked: number;
}
export interface DTaskStats {
  at: number;
  cpuPercent: number;
  memUsed: number;
  memLimit: number;
  netRxBytes: number;
  netTxBytes: number;
  blockRead: number;
  blockWrite: number;
  pids: number;
}
export type DRelocationCheckName = 'node-allowed' | 'node-ready' | 'capacity' | 'networks' | 'storage';
export interface DRelocationCheck {
  tenant?: string;
  app?: string;
  service?: string;
  from: string;
  to: string;
  ok: boolean;
  checks: { name: DRelocationCheckName | string; ok: boolean; detail?: string }[];
  volumes: { name: string; kind: string; node: string; step: 'move' | 'not-movable' | string }[];
  steps: ('app' | 'volume-move' | string)[];
}

/** POST …/observe (container-observe) 로그 결과. 한 번에 24 KiB까지이고 넘으면 truncated */
export interface DObserveLogs {
  node?: string;
  nativeID?: string;
  kind: string;
  logs?: { time: number; stream: string; text: string }[];
  truncated?: boolean;
  logDriver?: string;
  observedAt?: number;
}
/** 로그 정리 계획 (mydcd app-log-clear-plan). target을 그대로 POST에 실어 보낸다 */
export interface DLogClearPlan {
  clearable: boolean;
  driver: string;
  /** clearable이 false일 때: unsupported-log-driver */
  reason?: string;
  service: string;
  instance?: string;
  node?: string;
  target: string;
  inventoryRevision: number;
  targets: { key: string; service: string; instance?: string; kind?: string; node: string; nativeID?: string; startedAt?: number; logDriver?: string; generation: number; retained?: boolean; reason: 'target' | 'depends-on' | string }[];
}
/** mydcd app-log-clear-status. 실패는 op 결과로 본다(Failed 단계 없음) */
export interface DLogClearStatus {
  operation?: string;
  phase: 'Retiring' | 'Removed' | 'Recreating' | 'Succeeded' | string;
  target?: string;
  oldContainers?: unknown[];
  newContainers?: unknown[];
}

// ── 이미지 올리기·레이어 보기·태그 추가 (UI-88·89, 웹 데몬이 저장소 API를 직접 씀) ──

export interface DImageManifest {
  repository: string;
  ref: string;
  digest: string;
  mediaType: string;
  manifest: unknown;
  config?: { architecture?: string; os?: string; config?: { User?: string; Env?: string[]; Cmd?: string[]; Entrypoint?: string[]; WorkingDir?: string; ExposedPorts?: Record<string, unknown>; Labels?: Record<string, string> }; created?: string } & Record<string, unknown>;
  platforms?: { platform: string; digest: string }[];
  history: { created?: string; createdBy?: string; comment?: string; emptyLayer?: boolean }[];
  layers: { digest: string; mediaType: string; bytes: number; createdBy?: string }[];
}
export interface DLayerFile {
  path: string;
  bytes: number;
  mode: string;
  type: 'file' | 'dir' | 'symlink' | 'hardlink' | 'other' | string;
  link?: string;
  whiteout?: boolean;
}
export interface DLayerFiles {
  digest: string;
  files: DLayerFile[];
  truncated: boolean;
}
export interface DImageUpload {
  id: string;
  registry: string;
  fileName: string;
  bytes: number;
  chunkBytes: number;
  chunks: number;
  received: number;
  missing: number[];
  createdAt: string;
  expiresAt: string;
  inspect?: { state: 'running' | 'done' | 'failed' | string; error?: string; items?: { index: number; kind: 'image' | 'index' | string; refs: string[] | null; platforms: string[] | null; bytes: number; layers: number; digest?: string }[] };
  push?: { item: number; repository: string; tag: string; state: 'preparing' | 'pushing' | 'done' | 'failed' | 'canceled' | string; digest?: string; error?: string; layers: { digest: string; bytes: number; done: number; state: string }[]; startedAt: string; finishedAt?: string };
}

// ── 웹 데이터 자동 백업 (UI-C1, REQ-28 · 웹 데몬 계약 요청 중) ──
export interface DAutoBackup {
  enabled: boolean;
  /** 백업 파일을 웹 봉인 키로 잠그는지 (#112부터 늘 true) */
  sealed?: boolean;
  /** 봉인 키가 준비됐는지. false면 run·restore-from이 503 seal-unavailable */
  sealReady?: boolean;
  /** 서버 시각 HH:MM */
  at: string;
  keep: number;
  tenant?: string;
  volume?: string;
  /** 지금 백업이 도는 중 */
  running?: boolean;
  updatedBy?: string;
  updatedAt?: string;
  /** 고정 'mydc-web-backups/' */
  prefix: string;
  /** 웹의 자동 작업 계정. 없으면 아직 없음 */
  /** 자동 작업 계정 이름 (데몬 #119). 옛 목업은 {id, username} */
  account?: string | { id: string; username: string };
  /** 자동 작업 계정 id. 처음 로그인에 성공한 뒤부터 (#122) */
  accountId?: string;
  /** 자동 작업 계정에 그 폴더 위임이 있는지(데몬이 확인할 수 있을 때만) */
  granted?: boolean;
  last?: { at: string; ok: boolean; bytes?: number; path?: string; error?: string; by?: string };
  next?: string;
}
/** 데이터 저장소 파일 목록 한 줄(#270: digest는 오지 않음) */
export interface DVolumeFile {
  path: string;
  bytes: number;
  modifiedAt: string;
}

// ── 서버 고급 동작 ──
/** 서버 행의 가장 최근 비우기(데몬 #341). state는 mydcd 값(Running·Succeeded·Partial 등). 진행 수는 drain-status로 읽는다 */
export interface DNodeDrainProgress { operation: string; state: string }
/** 서버 고급 관리 계획에 나오는 Task 한 줄 (데몬 #335) */
export interface DNodePlanTask { tenant: string; app: string; service: string; task: string; node: string; standalone?: string; target?: string; generation?: number; revision?: number; movable: boolean; reason?: 'FIXED_VOLUME' | 'NO_TARGET' | 'PINNED_TO_NODE' | string }
export interface DNodeDrainJob { tenant: string; app: string; operation: string; target: string; services: string[] | null; tasks: number; moveVolume: boolean }
export interface DNodeDrainPlan { node: string; operation: string; expected: number; plan: string; code?: string; blockers: { code: string; detail?: string }[] | null; tasks: DNodePlanTask[] | null; jobs: DNodeDrainJob[] | null }
export interface DNodeDrainStatus { node: string; operation: string; state: string; total: number; moved: number; blocked: number; jobs: { tenant: string; app: string; operation: string; state: string; total: number; moved: number }[] | null }
export interface DNodeVoterPlan { node: string; epoch: number; expected: number; demotable: boolean; code?: string; blockers: { code: string; detail?: string }[] | null; votersBefore: number; votersAfter: number; quorumAfter: number; faultToleranceAfter: number; quorum: number; tolerates: number; pendingOperation?: string }

/** GET /diag/provider-log/state: 공급자 진단 로그 스위치 (UI-C1, mydc-web 몫). 시각은 RFC 3339 UTC */
export interface DProviderLogState {
  enabled: boolean;
  /** 켜져 있을 때만 */
  enabledAt?: string;
  /** username */
  enabledBy?: string;
  /** 켜져 있을 때만: 진단 도구가 읽었거나 새 항목이 생긴 마지막 때 */
  lastActivity?: string;
  /** 켜져 있을 때만: 저절로 꺼질 때(1시간 무활동과 켠 뒤 24시간 중 먼저 오는 것) */
  expiresAt?: string;
  /** user: 사람이 끔, idle: 1시간 쓰이지 않아 꺼짐, limit: 켠 지 24시간이 지남(활동이 있어도), restart: 웹 앱이 새로 시작함(늘 꺼진 채로 시작) */
  disabledReason?: 'user' | 'idle' | 'limit' | 'restart' | string;
  disabledAt?: string;
  /** 메모리에 모은 항목 수 */
  entries: number;
  /** 가장 새 항목의 seq */
  last: number;
}
/** POST /diag/provider-log/enable: 진단 도구용 임시 토큰. 이 응답에만 있고 웹은 어디에도 저장하지 않는다. 켜져 있을 때 다시 켜면 토큰이 바뀐다 */
export interface DProviderLogEnable {
  token: string;
  state: DProviderLogState;
}
export interface DProviderLogEntry {
  seq: number;
  at: string;
  /** dns:hostinger · acme:letsencrypt · acme:letsencrypt-staging · mydc-web */
  provider: string;
  conn?: string;
  /** GetZone, Apply, NewOrder … */
  op?: string;
  level: 'info' | 'warn' | 'error' | string;
  msg?: string;
  kind?: string;
  error?: string;
  attrs?: Record<string, unknown>;
  /** 요청·응답 본문은 비밀을 가리고 잘라 낸 문자열 */
  http?: { method: string; url: string; status?: number; durationMs: number; request?: string; response?: string; reqBytes?: number; respBytes?: number; headers?: Record<string, unknown> };
}
/** GET /diag/provider-log: entries는 늘 오래된 것부터 */
export interface DProviderLogPage {
  page: { entries: DProviderLogEntry[] | null; next: number; last: number; oldest: number; more: boolean };
  state: DProviderLogState;
}
