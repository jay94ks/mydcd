// SPDX-License-Identifier: Apache-2.0

// 화면이 쓰는 조회 함수. 계약 DTO(dto.ts)를 받아 화면 보기 모델(types.ts)로 바꾼다.
import { api, apiUrl, enc, q } from './client';
import type * as D from './dto';
import type * as V from './types';
import type { DnsRecord } from '../lib/dnsRecords';

/** sfcd Unix 초 → ISO. 0·없음은 undefined */
export const unix = (s?: number): string | undefined => (s ? new Date(s * 1000).toISOString() : undefined);
const arr = <T>(x: T[] | null | undefined): T[] => x ?? [];
const page = <A, B>(p: D.ListPage<A>, f: (a: A) => B): V.Page<B> => ({ items: arr(p.items).map(f), next: p.next ?? '', revision: p.revision, asOf: p.asOf });
const STALE_SEC = 120;

// ── 인증 ──
export function toSession(s: D.DSession): V.SessionView {
  return { user: s.user, tenants: arr(s.tenants), expiresAt: s.expiresAt, method: s.method === 'private-key' ? 'key' : s.method, rootRevision: s.rootRevision ?? 0 };
}

// ── 서버 ──
const PHASE_FROM_STATUS: Record<string, V.NodePhase> = { ready: 'ready', degraded: 'problem', unready: 'problem', unreachable: 'unknown', isolated: 'isolated', pending: 'joining', joining: 'joining', removed: 'removing', removing: 'removing' };
/** 표에 없는 서버 단계(draining 등)는 ready 칸이 있으면 그걸로, 없으면 모름 */
const summaryPhase = (s: D.DNodeSummary): V.NodePhase => PHASE_FROM_STATUS[s.status?.toLowerCase()] ?? (s.ready === undefined ? 'unknown' : s.ready ? 'ready' : 'problem');
const PHASE_FROM_MEMBER: Record<D.DMember['phase'], V.NodePhase> = { active: 'ready', isolated: 'isolated', pending: 'joining', removed: 'removing' };

export function fromSummary(s: D.DNodeSummary): V.NodeView {
  return {
    id: s.node,
    phase: summaryPhase(s),
    voter: !!s.role && s.role !== 'non-voter' && s.role !== 'pending',
    leader: s.role === 'leader',
    roleUnknown: s.role ? undefined : true,
    cpuPercent: s.cpuPercent,
    memory: s.memTotal ? { used: s.memUsed ?? 0, total: s.memTotal } : undefined,
    memUsed: s.memTotal ? undefined : s.memUsed,
    disk: s.diskTotal ? { used: s.diskUsed ?? 0, total: s.diskTotal } : undefined,
    stale: s.stale || undefined,
    cordoned: s.scheduling?.enabled || undefined,
    cordonedBy: s.scheduling?.cordonedBy || s.cordonedBy || undefined,
    cordonedAt: s.scheduling?.cordonedAt || s.cordonedAt || undefined,
    containers: s.containers,
    clusterApps: s.clusterApps,
    observedAt: unix(s.observedAt),
    observeLimitSeconds: s.observeLimitSeconds,
    build: s.build,
  };
}

const BUILD_OFF: Record<string, string> = {
  ENGINE_BUILD_OFF: '이 서버의 엔진이 빌드를 끔(node.yaml)',
  WORKLOAD_OFF: '이 서버는 작업 모듈이 꺼져 있음',
  UNKNOWN: '서버의 최근 보고가 없어 빌드할 수 있는지 모름',
};
/** 빌드 서버로 고를 수 없는 이유. UNKNOWN은 서버가 정하므로 막지 않고 알리기만 한다(undefined = 막지 않음) */
export function buildBlocked(n?: { build?: { enabled: boolean; reason?: string } }): string | undefined {
  if (!n?.build || n.build.enabled || n.build.reason === 'UNKNOWN') return undefined;
  return BUILD_OFF[n.build.reason ?? ''] ?? `빌드할 수 없음(${n.build.reason ?? '이유 모름'})`;
}
/** 빌드 시작이 build-disabled(409)로 거절됐을 때 (#693) */
export const BUILD_OFF_TEXT = '이 서버는 지금 빌드를 하지 않아요 (서버 상세의 빌드 항목 이유 참고).';

/** 서버 상세에 보일 빌드 상태 글 */
export function buildText(n?: { build?: { enabled: boolean; reason?: string } }): string | undefined {
  if (!n?.build) return undefined;
  return n.build.enabled ? '빌드함' : BUILD_OFF[n.build.reason ?? ''] ?? `빌드하지 않음(${n.build.reason ?? '이유 모름'})`;
}

/** members(가입 정보) + node-summary(관측)를 합친다. 관측이 없으면 가입 정보만. */
export function mergeNodes(members: D.DMember[], summaries: D.DNodeSummary[]): V.NodeView[] {
  const sum = new Map(summaries.map((s) => [s.node, s]));
  const out: V.NodeView[] = members.map((m) => {
    const s = sum.get(m.id);
    const base = s ? fromSummary(s) : undefined;
    const memberPhase = PHASE_FROM_MEMBER[m.phase] ?? 'unknown';
    return {
      ...(base ?? { id: m.id, phase: memberPhase, voter: m.voter, leader: false }),
      id: m.id,
      endpoint: m.endpoint,
      systemAddress: m.systemAddress || undefined,
      key: m.key,
      voter: m.voter,
      admitsWork: m.admitsWork,
      cordoned: m.cordoned ?? m.scheduling?.enabled,
      cordonReason: m.cordonReason || undefined,
      cordonedBy: m.cordonedBy || m.scheduling?.cordonedBy || undefined,
      cordonedAt: m.cordonedAt || m.scheduling?.cordonedAt || undefined,
      schedulingRevision: m.scheduling?.revision,
      joinRevision: m.joinRevision,
      drain: m.drain,
      identity: m.identity,
      identityRotatedAt: m.identityRotatedAt || undefined,
      revision: m.revision,
      pendingOperation: m.pendingOperation,
      join: m.join,
      // 가입 대기·제거 중은 가입 정보가 우선
      phase: memberPhase === 'joining' || memberPhase === 'removing' || memberPhase === 'isolated' ? memberPhase : (base?.phase ?? memberPhase),
    };
  });
  for (const s of summaries) if (!members.some((m) => m.id === s.node)) out.push(fromSummary(s));
  return out;
}

/** tenant를 주면 그 작업 공간 보기(관리자가 아닐 때). 가입 정보(/nodes)는 시스템 관리자만이라 그때는 요약 행만 쓴다 */
export async function nodesOverview(signal?: AbortSignal, tenant?: string): Promise<V.NodesOverview> {
  if (tenant) {
    const sums = await pagedRows<D.DNodeSummary>(`/nodes/summary${tenantQ(tenant)}`, signal);
    return { nodes: sums.map(fromSummary), revision: 0, asOf: new Date().toISOString() };
  }
  const [m, s] = await Promise.all([api.get<D.DMembersPage>('/nodes', signal), pagedRows<D.DNodeSummary>('/nodes/summary', signal).catch(() => [] as D.DNodeSummary[])]);
  return { nodes: mergeNodes(arr(m.items), s), voters: m.voters, quorum: m.quorum, revision: m.revision, asOf: m.asOf };
}

/** 새 배치 제외·되돌리기, 서버 이미지 캐시 정리 */
/** 서버 제거 (remove-node, #128). operation·epoch는 데몬 기본값을 쓴다 */
export const nodeRemovePath = (node: string) => `/nodes/${enc(node)}/remove`;
/** 격리·복귀 (#133). 본문은 {opId}면 되고 이미 그 상태면 409 unchanged */
export const nodeIsolatePath = (node: string, act: 'isolate' | 'restore') => `/nodes/${enc(node)}/${act}`;
/** 서버 제거 미리 보기 (REQ-52, 데몬 #335) */
export type NodeRemovePlan = {
  node: string;
  epoch: number;
  expected: number;
  removable: boolean;
  blockers: { code: string; detail?: string }[];
  votersBefore: number;
  votersAfter: number;
  quorumAfter: number;
  faultToleranceAfter: number;
  tasks: D.DNodePlanTask[];
  storage: { id: string; path: string; generation?: number; revision?: number; volumes: string[] | null; retained?: boolean; draining: boolean; closed: boolean }[];
  volumes: { tenant: string; app?: string; id: string; fixed: boolean; retained?: boolean; generation?: number; move?: unknown }[];
  activity?: { resources: number; flows: number; writers: number; leases: number; cdJobs: number };
  nativeClosed?: boolean;
  pendingOperation?: string;
};
const normRemovePlan = <T extends Partial<NodeRemovePlan>>(r: T) => ({ ...r, blockers: arr(r.blockers), tasks: arr(r.tasks), storage: arr(r.storage), volumes: arr(r.volumes) });
export const nodeRemovePlan = async (node: string, signal?: AbortSignal): Promise<NodeRemovePlan> => normRemovePlan(await api.get<NodeRemovePlan>(`/nodes/${enc(node)}/remove-plan`, signal)) as NodeRemovePlan;
/** 강제 제거 계획: remove-plan 모양 + operation·forceable·code·plan·probe */
export type NodeForceRemovePlan = NodeRemovePlan & { operation: string; forceable: boolean; code?: string; plan: string; probe?: { responding: boolean; startedAt?: string; finishedAt?: string } };
export const nodeCordonPath = (node: string, on: boolean) => `/nodes/${enc(node)}/${on ? 'cordon' : 'uncordon'}`;
export const nodeImagePrunePlan = async (node: string, signal?: AbortSignal) => {
  const r = await api.get<D.DNodeImagePrunePlan>(`/nodes/${enc(node)}/image-prune-plan`, signal);
  return { ...r, images: arr(r.images) };
};
export const nodeImagePrunePath = (node: string) => `/nodes/${enc(node)}/image-prune`;
/** 정리 진행 (데몬 #384). 웹에서 보낸 작업은 op-<opId> */
export const imagePrune = async (opId: string, signal?: AbortSignal) => {
  const r = await api.get<D.DImagePrune>(`/image-prunes/${enc(`op-${opId}`)}`, signal);
  return { ...r, images: arr(r.images), parts: arr(r.parts) };
};
export const invitationSummary = (node: string, signal?: AbortSignal) => api.get<D.DInvitationSummary>(`/nodes/${enc(node)}/invitation/summary`, signal);
export const invitationPath = (node: string) => `/nodes/${enc(node)}/invitation`;
export async function node(id: string, signal?: AbortSignal): Promise<V.NodeView> {
  const o = await nodesOverview(signal);
  const n = o.nodes.find((x) => x.id === id);
  if (!n) throw Object.assign(new Error('서버를 찾지 못했습니다.'), { name: 'NotFound' });
  return n;
}

export function toTask(t: D.DTask): V.TaskView {
  const observed: V.TaskView['observed'] = t.observed === 'created' ? 'starting' : t.observed === 'missing' ? 'unknown' : t.observed;
  const health: V.TaskView['health'] = t.health === 'healthy' ? 'pass' : t.health === 'unhealthy' ? 'fail' : t.health === 'starting' ? 'starting' : 'none';
  return {
    id: `${t.tenant}/${t.app}/${t.service}/${t.instance}`,
    tenant: t.tenant,
    app: t.app,
    service: t.service,
    instance: t.instance,
    node: t.node,
    image: t.image,
    desired: t.desired,
    observed,
    health,
    generation: t.generation,
    restarts: t.restarts,
    exitCode: t.exitCode,
    startedAt: unix(t.startedAt),
    observedAt: unix(t.observedAt) ?? new Date(0).toISOString(),
    stale: !t.observedAt || Date.now() / 1000 - t.observedAt > STALE_SEC,
    lastCheck: t.lastCheck,
  };
}

export const nodeTasks = async (id: string, tenant: string | undefined, signal?: AbortSignal) => page(await api.get<D.ListPage<D.DTask>>(`/nodes/${enc(id)}/tasks${q({ tenant })}`, signal), toTask);
const toRoot = (r: D.DStorageRoot): V.StorageRoot => ({ node: r.node, name: r.id, path: r.path, tenants: arr(r.tenants), draining: r.draining, revision: r.revision, generation: r.generation, allTenants: r.allTenants || undefined, capacityBytes: r.capacityBytes, isDefault: r.default || undefined, closed: r.closed, attested: r.attested, volumes: r.volumes });
export const nodeStorage = async (id: string, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DStorageRoot>>(`/nodes/${enc(id)}/storage`, signal), toRoot);

/** 클러스터 전체 저장 경로(node-storage, 시스템 관리자만. 작업 공간 관리자는 REQ-30 전까지 못 읽음) */
export const storageRoots = async (signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DStorageRoot>>(`/storage`, signal), toRoot);
/** REQ-30·58: 이 작업 공간이 쓸 수 있는 저장 경로(관리 권한, 보기만이면 403). 한 쪽 8개라 끝까지 읽는다 */
export const tenantStorage = async (t: string, signal?: AbortSignal) => {
  const p = await allPages<D.DTenantStorageRoot>(`/t/${enc(t)}/storage`, signal);
  return {
    ...p,
    items: p.items.map((r): V.StorageRoot => ({ node: r.node, name: r.id, path: r.root?.path ?? '', tenants: [t], draining: r.draining, revision: r.revision, generation: r.generation, volumes: r.volumes, allowed: r.allowed, isDefault: r.id === 'default' || undefined })),
  };
};
/** 새로 고를 수 있는 경로: 허용됐고 꺼내는 중이 아님 */
export const usableRoot = (r: V.StorageRoot) => !r.draining && r.allowed !== false;
const DISK_PURPOSE: Record<string, string> = { system: '시스템', 'container-runtime': '컨테이너 이미지·실행', 'storage-root': 'Seafield Cluster 저장 경로' };
/** next를 따라 끝까지 읽는다(최대 20쪽). 예전 데몬처럼 배열이면 그대로 */
async function pagedRows<T>(path: string, signal?: AbortSignal): Promise<T[]> {
  const out: T[] = [];
  let after: string | undefined;
  for (let i = 0; i < 20; i++) {
    const sep = path.includes('?') ? '&' : '?';
    const r = await api.get<D.ListPage<T> | T[]>(after ? `${path}${sep}${new URLSearchParams({ after })}` : path, signal);
    if (Array.isArray(r)) return r;
    out.push(...arr(r.items));
    const next = (r as { next?: string }).next;
    if (!next || next === after) break;
    after = next;
  }
  return out;
}
const tenantQ = (tenant?: string) => (tenant ? `?${new URLSearchParams({ tenant })}` : '');
/** 서버 장치 목록 (#689): 시스템 관리자가 tenant 없이 서버 하나를 물을 때 첫 페이지의 devices. 옛 데몬은 없음(undefined) */
export async function nodeDevices(id: string, signal?: AbortSignal): Promise<D.DNodeDevices | undefined> {
  const r = await api.get<(D.ListPage<D.DNodeDisk> & { devices?: D.DNodeDevices }) | D.DNodeDisk[]>(`/nodes/${enc(id)}/disks`, signal);
  if (Array.isArray(r) || !r.devices) return undefined;
  const fix = <T,>(x: T[] | null | undefined): T[] => x ?? [];
  return {
    ...r.devices,
    recorded: fix(r.devices.recorded),
    disks: fix(r.devices.disks).map((d) => ({
      ...d,
      purposes: fix(d.purposes),
      parts: fix(d.parts).map((p) => ({ ...p, mounts: fix(p.mounts), purposes: fix(p.purposes), storageRoots: fix(p.storageRoots), holders: fix(p.holders).map((h) => ({ ...h, mounts: fix(h.mounts) })) })),
    })),
  };
}
export type DiskAction = D.DDiskOp['action'];
/** 디스크 작업 (#689 3단계): 시스템 관리자만. 같은 opId를 다시 보내면 처음 결과를 돌려준다 */
export const diskAction = (node: string, disk: string, action: DiskAction, body: { opId: string; part: string; serial?: string; wwn?: string; size?: number; tableId?: string; uuid?: string; mountPath?: string; label?: string }) =>
  api.post<D.DDiskOp>(`/nodes/${enc(node)}/disks/${enc(disk)}/${action}`, body);
/** 서버 방화벽 (node-firewall, 시스템 관리자). 응답은 늘 200이고 실패는 code로 온다 */
export const nodeFirewall = (node: string, signal?: AbortSignal) => api.get<D.DFirewallResult>(`/nodes/${enc(node)}/firewall`, signal);
/** 읽은 revision과 바꿀 것만(delta) 보낸다. 같은 opId를 다시 보내면 처음 결과 */
export const nodeFirewallChange = (node: string, body: { opId: string; revision: number } & D.DFirewallDelta) => api.post<D.DFirewallResult>(`/nodes/${enc(node)}/firewall`, body);
/** 변경 기록 최신부터 50건. before: 이 revision보다 앞 */
export const nodeFirewallLog = (node: string, before?: number, signal?: AbortSignal) => api.get<D.DFirewallResult>(`/nodes/${enc(node)}/firewall/log${q({ before })}`, signal);
/** 오래 걸리는 포맷(running)의 상태. 없으면 404 */
export const diskOperation = (node: string, opId: string, signal?: AbortSignal) => api.get<D.DDiskOp>(`/nodes/${enc(node)}/disk-operations/${enc(opId)}`, signal);
/** tenant를 빼면 클러스터 전체(시스템 관리자만, 아니면 403). 관리자가 아니면 그 작업 공간의 볼륨 관리 권한으로 허용 저장 경로 디스크만 */
export async function nodeDisks(id: string, signal?: AbortSignal, tenant?: string): Promise<V.DiskView[]> {
  const rows = await pagedRows<D.DNodeDisk>(`/nodes/${enc(id)}/disks${tenantQ(tenant)}`, signal);
  return rows.map((d) => {
    const purposes = d.purposes?.length ? d.purposes : [d.purpose];
    const roots = d.storageRoots?.length ? d.storageRoots : d.storageRootID ? [d.storageRootID] : [];
    return {
      root: d.storageRootID ?? roots[0],
      roots,
      mount: d.mount,
      device: d.device || undefined,
      fs: d.fsType,
      purpose: purposes.map((p) => DISK_PURPOSE[p] ?? p).join(' · ') + (roots.length ? ` ${roots.join(', ')}` : ''),
      total: d.total,
      used: d.used,
      free: d.free,
      stale: d.stale || undefined,
    };
  });
}

/** 원장 세대. 데몬이 아직 주지 않으면 undefined */
export async function ledger(signal?: AbortSignal): Promise<{ epoch?: number; revision?: number }> {
  const r = await api.get<D.DMembersPage>('/nodes', signal);
  return { epoch: r.ledgerEpoch, revision: r.ledgerRevision };
}

export async function raft(signal?: AbortSignal): Promise<V.RaftView> {
  const r = await api.get<D.DRaftStatus>('/raft', signal);
  const servers = arr(r.servers);
  const voters = r.voters ?? servers.filter((s) => s.suffrage === 'voter').length;
  const quorumSize = r.quorum || Math.floor(voters / 2) + 1;
  return {
    quorum: !r.stale && !!r.leader && (r.respondingVoters === undefined || r.respondingVoters >= quorumSize),
    responding: r.respondingVoters,
    observedBy: r.observedBy || undefined,
    leader: r.leader,
    term: r.term,
    commitIndex: r.commitIndex,
    configIndex: r.configurationIndex,
    voters,
    quorumSize,
    tolerate: Math.max(0, voters - quorumSize),
    snapshotIndex: r.lastSnapshotIndex,
    snapshotAt: unix(r.lastSnapshotAt),
    members: servers.map((s) => ({ node: s.node, voter: s.suffrage === 'voter', role: s.role, match: s.matchIndex, applied: s.appliedIndex, lag: s.lag, logBytes: s.logBytes, logEntries: s.logEntries, lastContactAt: unix(s.lastContactAt), stale: s.stale || undefined })),
    events: arr(r.elections).map((e) => ({ at: unix(e.at) ?? '', text: `임기 ${e.term} 리더 ${e.leader}${e.reason ? ` · ${e.reason}` : ''}` })),
  };
}

/** tenant를 빼면 클러스터 전체(시스템 관리자만). rtt·손실은 클러스터 전체 보기에서만 온다 */
export async function mesh(signal?: AbortSignal, tenant?: string): Promise<V.MeshLink[]> {
  return (await pagedRows<D.DMeshLink>(`/mesh${tenantQ(tenant)}`, signal)).map((l) => ({
    a: l.nodeA,
    b: l.nodeB,
    state: l.state === 'degraded' ? 'slow' : l.state,
    rttMs: l.state === 'pending' ? undefined : l.rttMillis,
    lossPct: l.state === 'pending' ? undefined : l.lossPercent,
    observedAt: unix(l.observedAt) ?? '',
    stale: l.stale || undefined,
    dialer: l.dialer === l.nodeA || l.dialer === l.nodeB ? l.dialer : undefined,
  }));
}

// ── 앱 ──
export function toApp(a: D.DAppView): V.AppView {
  const st = a.operation?.status ?? '';
  const running = st === 'pending' || st === 'running';
  const health: V.Health = running ? 'progressing' : a.health === 'healthy' ? 'healthy' : a.health === 'degraded' ? 'degraded' : a.health === 'unhealthy' ? 'unhealthy' : 'unknown';
  return {
    tenant: a.tenant,
    app: a.app,
    deployment: a.deployment,
    revision: a.revision,
    health,
    retiring: !!a.retiring,
    claims: a.claims,
    lastOp: a.operation?.id ? { id: a.operation.id, status: st, failed: !!a.operation.failed, at: unix(a.operation.completedAt), submitter: a.operation.submitter } : undefined,
    cd: a.cd ? { repository: a.cd.repository, branch: a.cd.branch, mode: a.cd.mode, paused: a.cd.paused, running: a.cd.running, sourceError: a.cd.sourceError, candidate: a.cd.candidate || undefined, candidateDigest: a.cd.candidateDigest || undefined } : undefined,
    observedAt: unix(a.observedAt),
  };
}

export async function dashboard(tenant: string | undefined, signal?: AbortSignal): Promise<V.DashboardView> {
  const [d, unknownOps] = await Promise.all([api.get<D.DDashboard>(`/dashboard${q({ tenant })}`, signal), opsList('unknown', signal).catch(() => [] as V.OpView[])]);
  const nodes = arr(d.nodes).map(fromSummary);
  const apps = arr(d.apps).map(toApp).filter((a) => !a.retiring);
  const attention: V.AttentionItem[] = [
    ...apps.filter((a) => a.health === 'degraded' || a.health === 'unhealthy').map((a) => ({ kind: 'problem' as const, text: `${a.tenant}/${a.app} · ${a.health === 'unhealthy' ? '문제' : '일부 문제'}`, at: a.observedAt ?? d.asOf, link: appPath(a.tenant, a.app) })),
    ...nodes.filter((n) => n.disk && n.disk.used / n.disk.total >= 0.8).map((n) => ({ kind: 'disk' as const, text: `${n.id} 디스크 ${Math.round((n.disk!.used / n.disk!.total) * 100)}% 사용`, at: n.observedAt ?? d.asOf, link: `/servers/${n.id}` })),
    ...nodes.filter((n) => n.phase === 'unknown' || n.phase === 'problem').map((n) => ({ kind: 'problem' as const, text: `${n.id} ${n.phase === 'unknown' ? '연락 안 됨' : '일부 문제'}`, at: n.observedAt ?? d.asOf, link: `/servers/${n.id}` })),
    ...unknownOps.map((o) => ({ kind: 'unknown-op' as const, text: `작업 ${o.id.slice(0, 8)} · ${o.action}${o.target ? ` · ${o.target}` : ''}`, at: o.submittedAt, link: `/system/ops?focus=${o.id}` })),
    ...apps.filter((a) => a.health === 'progressing').map((a) => ({ kind: 'progress' as const, text: `${a.app} · ${a.lastOp?.status ?? '진행 중'}`, at: a.observedAt ?? d.asOf, link: appPath(a.tenant, a.app) })),
  ];
  return { scope: tenant ? 'tenant' : 'cluster', nodes, apps, attention, asOf: d.asOf };
}

export const appPath = (tenant: string, app: string) => `/deploy/apps/${enc(tenant)}/${enc(app)}`;
export const apps = async (tenant: string, signal?: AbortSignal) => {
  const p = page(await api.get<D.ListPage<D.DAppView>>(`/t/${enc(tenant)}/apps`, signal), toApp);
  return { ...p, items: p.items.filter((a) => !a.retiring) };
};
export async function app(tenant: string, name: string, signal?: AbortSignal): Promise<V.AppView> {
  const p = await apps(tenant, signal);
  const a = p.items.find((x) => x.app === name);
  if (!a) throw Object.assign(new Error('이 앱이 없거나 볼 권한이 없습니다.'), { name: 'NotFound' });
  return a;
}
export const appTasks = async (tenant: string, name: string, signal?: AbortSignal) => page(await api.get<D.ListPage<D.DTask>>(`/t/${enc(tenant)}/apps/${enc(name)}/tasks`, signal), toTask);
export async function appSource(tenant: string, name: string, version = 0, signal?: AbortSignal): Promise<V.AppSource> {
  const s = await api.get<D.DAppSource>(`/t/${enc(tenant)}/apps/${enc(name)}/source${q({ version: version || undefined })}`, signal);
  return { version: s.version, yaml: s.yaml, digest: s.digest, submitter: s.submitter, operation: s.operation, acceptedAt: s.acceptedAt };
}
export const appRevisions = async (tenant: string, name: string, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DAppRevision>>(`/t/${enc(tenant)}/apps/${enc(name)}/revisions`, signal), (r): V.AppRevision => ({ version: r.version, digest: r.digest, submitter: r.submitter, operation: r.operation, status: r.status, at: unix(r.acceptedAt) ?? '' }));

/** 계획 diff 문자열(unified)을 줄로. 머리줄(---/+++/@@)은 뺀다. */
export function parseDiff(text: string): V.DiffLine[] {
  return text
    .replace(/\n$/, '')
    .split('\n')
    .filter((l) => !/^(---|\+\+\+|@@)/.test(l))
    .map((l) => (l.startsWith('+') ? { op: '+', text: l.slice(1) } : l.startsWith('-') ? { op: '-', text: l.slice(1) } : { op: ' ', text: l.startsWith(' ') ? l.slice(1) : l }));
}

export async function plan(tenant: string, yaml: string, deployment?: string): Promise<V.PlanReply> {
  const p = await api.post<D.DAppPlan>(`/t/${enc(tenant)}/apps/plan`, { yaml, diff: true, ...(deployment ? { deployment } : {}) });
  const services = arr(p.services);
  return {
    app: p.app,
    digest: p.digest,
    length: p.length,
    services,
    counts: {
      add: services.filter((s) => s.change === 'add').length,
      change: services.filter((s) => s.change === 'update').length,
      keep: services.filter((s) => s.change === 'keep').length,
      remove: services.filter((s) => s.change === 'remove').length,
    },
    diff: p.diff ? parseDiff(p.diff) : [],
  };
}

export const archived = async (tenant: string, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DArchived>>(`/t/${enc(tenant)}/archived`, signal), (a): V.ArchivedApp => ({ key: a.key, tenant: a.tenant, app: a.app, version: a.version, digest: a.digest, downBy: a.downBy, downAt: a.downAt, downOp: a.downOp, volumes: arr(a.volumes) }));
export const archivedSource = async (tenant: string, key: string, signal?: AbortSignal) => (await api.get<D.DArchived>(`/t/${enc(tenant)}/archived/${enc(key)}`, signal)).yaml ?? '';
export const purgeArchived = (tenant: string, key: string, confirm: string) => api.post<unknown>(`/t/${enc(tenant)}/archived/${enc(key)}/purge`, { confirm });

export const uploads = async (tenant: string, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DUpload>>(`/t/${enc(tenant)}/uploads`, signal), (u): V.UploadView => {
    const parts = Math.max(1, Math.ceil(u.length / (1 << 20)));
    return { id: u.id, app: u.app, deployment: u.deployment, parts, missing: arr(u.missing) };
  });

// ── 저장 경로(UI-14) · 작업 공간 서버 한도(UI-16) ──
// 데몬이 sfcd payload(add/set-node-storage-policy/drain/remove-node-storage, set-node-quota)를 만든다.
export const storagePath = (node: string, id?: string) => `/nodes/${enc(node)}/storage${id ? `/${enc(id)}` : ''}`;
export const limitPath = (t: string, node: string) => `/t/${enc(t)}/limits/${enc(node)}`;

// ── 작업 공간 · 사용자 ──
export async function tenantList(signal?: AbortSignal): Promise<V.TenantAccess[]> {
  const r = await api.get<D.ListPage<D.DTenantView> | D.DTenantView[]>('/tenants', signal);
  return Array.isArray(r) ? r : arr(r.items);
}
export const tenantMembers = async (t: string, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DTenantMember>>(`/tenants/${enc(t)}/members`, signal), (m): V.TenantMember => ({ user: m.user, username: m.username, role: m.role, enabled: m.enabled, revision: m.revision }));
export async function tenantRetirement(t: string, signal?: AbortSignal): Promise<V.TenantRetirement> {
  const r = await api.get<D.DTenantRetirement>(`/tenants/${enc(t)}/retirement`, signal);
  const ready = r.ready ?? (r.retiring && r.ownerCount > 0 && r.closedOwners >= r.ownerCount && r.remainingCount === 0);
  return { retiring: r.retiring, targetCount: r.targetCount, ownerCount: r.ownerCount, closedOwners: r.closedOwners, remainingCount: r.remainingCount, remaining: arr(r.remaining), operation: r.operation || undefined, revision: r.revision, phase: r.phase, ready };
}
/** 공유 자원 전체 (UI-A2): resources 한 쪽. 다음 쪽은 ?after= */
export const resourcesPage = async (t: string, after?: string, signal?: AbortSignal) => {
  const r = await api.get<D.ListPage<D.DResourceEntry>>(`/t/${enc(t)}/resources${q({ after })}`, signal);
  return { items: arr(r.items), next: r.next ?? '', revision: r.revision };
};
/** 가상 브릿지 (UI-5D): resources를 끝까지 읽어 bridge 행만. revision은 망 목록과 같은 resources revision */
export async function bridges(t: string, signal?: AbortSignal): Promise<{ items: V.BridgeView[]; revision: number }> {
  const out: V.BridgeView[] = [];
  let after: string | undefined;
  let revision = 0;
  for (let i = 0; i < 20; i++) {
    const r = await api.get<D.ListPage<D.DResourceEntry>>(`/t/${enc(t)}/resources${q({ after })}`, signal);
    revision = r.revision ?? revision;
    for (const e of arr(r.items)) if (e.bridge) out.push({ ...e.bridge, key: e.key, ports: arr(e.bridge.ports), approvals: arr(e.bridge.approvals) });
    if (!r.next || r.next === after) break;
    after = r.next;
  }
  return { items: out, revision };
}
/** 다른 작업 공간이 브릿지를 받도록 연 망(bridge-inbound, 바뀌는 중 아님). 만들기 창의 잇는 망 고르기 (#728) */
export const bridgeEndpoints = async (t: string, peer: string, signal?: AbortSignal) =>
  arr((await api.get<{ tenant: string; items: { tenant: string; network: string }[] | null }>(`/t/${enc(t)}/bridge-endpoints?tenant=${enc(peer)}`, signal)).items);
export const bridgePath = (t: string, b?: { owner: string; name: string }) => `/t/${enc(t)}/bridges${b ? `/${enc(b.owner)}/${enc(b.name)}` : ''}`;
export const tenantLimits = async (t: string, signal?: AbortSignal) =>
  arr((await api.get<D.ListPage<D.DResourceEntry>>(`/t/${enc(t)}/resources`, signal)).items)
    .filter((e) => e.limit)
    .map((e) => e.limit!) as V.NodeLimit[];

const credKind = (m: string): V.UserCredential['kind'] => (m === 'private-key' ? 'key' : m === 'token' ? 'token' : 'password');
export const toUser = (u: D.DUserRecord): V.UserRecord => ({
  id: u.id,
  username: u.username,
  enabled: u.enabled,
  systemAdmin: u.systemAdmin,
  revision: u.revision,
  accountRevision: u.accountRevision,
  invite: u.invite ?? undefined,
  credentials: arr(u.credentials).map((c) => ({ id: c.id, kind: credKind(c.method), publicKey: c.publicKey && /[1-9a-f]/i.test(c.publicKey) ? c.publicKey : undefined, enabled: c.enabled, label: c.label || undefined, createdAt: c.createdAt, createdBy: c.createdBy, lastUsedAt: c.lastUsedAt, expiresAt: c.expiresAt, tail: c.tail, approvalKey: c.approvalKey })),
});
export const users = async (signal?: AbortSignal) => page(await api.get<D.ListPage<D.DUserRecord>>('/users', signal), toUser);
export const user = async (u: string, signal?: AbortSignal) => toUser(await api.get<D.DUserRecord>(`/users/${enc(u)}`, signal));
export async function myCredentials(signal?: AbortSignal): Promise<V.OwnCredentials> {
  const r = await api.get<D.DOwnCredentials>('/me/credentials', signal);
  return { userId: r.id, username: r.username, accountRevision: r.accountRevision ?? r.revision, clusterId: r.clusterId, credentials: toUser(r).credentials };
}

// ── 공유 자원 ──
/** TUN 망의 서버 쌍 연결 */
export const networkTunnels = async (t: string, name: string, signal?: AbortSignal) => arr((await api.get<{ items: D.DTunnelLink[] | null }>(`/t/${enc(t)}/networks/${enc(name)}/tunnels`, signal)).items);
export const tunnelReconnectPath = (t: string, name: string) => `/t/${enc(t)}/networks/${enc(name)}/tunnels/reconnect`;
/** 서버 화면용: 같은 동작(POST {opId}) */
export const nodeTunnelReconnectPath = (node: string, peer: string) => `/nodes/${enc(node)}/tunnels/${enc(peer)}/reconnect`;
/** 다시 연결 진행. operation = 'op-' + opId */
export const tunnelReconnect = (opId: string, signal?: AbortSignal) => api.get<D.DTunnelReconnect>(`/tunnel-reconnects/${enc(`op-${opId}`)}`, signal);
export const networks = async (t: string, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DResourceEntry>>(`/t/${enc(t)}/networks`, signal), (e): V.NetworkView => ({ key: e.key, name: e.network!.name, kind: e.network!.kind, cidr: e.network!.cidr, nodes: arr(e.network!.nodes), revision: e.network!.revision, dns: e.network!.dns && { ...e.network!.dns, zone: e.network!.dns.zone.replace(/\.$/, ''), upstreams: e.network!.dns.upstreams ?? undefined }, members: arr(e.network!.members).map((mb) => ({ node: mb.node, cidr: mb.cidr, draining: mb.draining, resolver: mb.resolver, dns: mb.dns && { state: mb.dns.state, ready: mb.dns.ready, resolvers: arr(mb.dns.resolvers) }, phase: mb.change && mb.change.phase !== 'committed' && mb.change.phase !== 'cancelled' ? mb.change.phase : undefined })), toggles: arr(e.network!.toggles), apps: e.network!.apps, standalones: e.network!.standalones }));
export const networkPath = (t: string, name: string) => `/t/${enc(t)}/networks/${enc(name)}`;
export const networkChange = async (t: string, name: string, signal?: AbortSignal) => {
  const d = await api.get<D.DNetworkChange>(`${networkPath(t, name)}/change`, signal);
  return { ...d, members: arr(d.members), closure: arr(d.closure) };
};
const usersOf = async (path: string, signal?: AbortSignal) => {
  const d = await api.get<D.DResourceUsers>(path, signal);
  return { ...d, users: arr(d.users).map((u) => ({ ...u, selection: arr(u.selection) })) };
};
/** 망을 쓰는 앱 서비스·단독 컨테이너 */
export const networkUsers = (t: string, name: string, signal?: AbortSignal) => usersOf(`${networkPath(t, name)}/users`, signal);
/** 저장소를 붙인 앱 서비스·단독 컨테이너 */
export const volumeUsers = (t: string, name: string, app: string | undefined, signal?: AbortSignal) => usersOf(`${volumePath(t, name)}/users${app ? `?app=${enc(app)}` : ''}`, signal);
export const backupLimits = async (t: string, node: string, signal?: AbortSignal) => arr((await api.get<{ items: D.DBackupLimit[] }>(`/t/${enc(t)}/backup-limits?node=${enc(node)}`, signal)).items);
export const backupLimitPath = (t: string, node: string) => `/t/${enc(t)}/backup-limits/${enc(node)}`;
const toVolume = (v: D.DVolume): V.VolumeView => ({ key: v.key, name: v.name, kind: v.kind, node: v.node, storage: v.storage, app: v.app, consumers: v.consumers, capacityBytes: v.capacityBytes, usedBytes: v.usedBytes ?? undefined, usageObservedAt: v.usageObservedAt ? new Date(v.usageObservedAt).toISOString() : undefined, retain: v.retain, revision: v.revision, phase: v.phase, movePhase: v.movePhase, targetNode: v.targetNode, moveId: v.moveID, retained: arr(v.retained), writer: v.writer });
export const volumes = async (t: string, signal?: AbortSignal) => page(await api.get<D.ListPage<D.DVolume>>(`/t/${enc(t)}/volumes`, signal), toVolume);
export const routes = async (t: string, signal?: AbortSignal) => {
  const r = await api.get<D.DRoutesPage>(`/t/${enc(t)}/routes`, signal);
  return { items: arr(r.items).map((x) => ({ ...x, ports: arr(x.ports), approvals: arr(x.approvals) })), networksRevision: r.networksRevision };
};
export const routePath = (t: string, r?: { sourceTenant: string; id: string }) => `/t/${enc(t)}/routes${r ? `/${enc(r.sourceTenant)}/${enc(r.id)}` : ''}`;
/** 다른 작업 공간이 연결 받는 쪽으로 연 망. 받는 쪽 망 고르기에 쓴다 */
export const routeEndpoints = async (t: string, dest: string, signal?: AbortSignal) =>
  arr((await api.get<{ items: { tenant: string; network: string; node: string; pool: string }[] | null }>(`/t/${enc(t)}/route-endpoints?tenant=${enc(dest)}`, signal)).items);
/** 데이터 저장소 하나의 끝점. 같은 이름이 여러 앱에 있으면 app을 함께 준다(409 ambiguous) */
export const volumePath = (t: string, name: string) => `/t/${enc(t)}/volumes/${enc(name)}`;
export const volumeDetail = async (t: string, name: string, app: string | undefined, signal?: AbortSignal) => {
  const d = await api.get<D.DVolumeDetail>(`${volumePath(t, name)}${app ? `?app=${enc(app)}` : ''}`, signal);
  const iso = (t: number | string) => (typeof t === 'number' ? new Date(t * 1000).toISOString() : t);
  return { volume: toVolume(d.volume), backups: arr(d.backups).map((b) => ({ ...b, createdAt: iso(b.createdAt) })), restores: arr(d.restores) };
};
/** 옮기기 계획(UI-64). node를 주면 데몬이 지금 앱 정의에 새 서버를 적는다 */
export const volumeMovePlan = async (t: string, name: string, body: { app?: string; node: string }) => {
  const p = await api.post<D.DVolumeMovePlan>(`${volumePath(t, name)}/move-plan`, body);
  return { ...p, services: arr(p.services) };
};
/** 보관함 하나: 작업 공간 보관함(/t/{t}/vault) 또는 클러스터 보관함(/vault, 시스템 관리자, 웹 계약 대기). root는 뿌리 묶음 ID */
export interface VaultScope {
  base: string;
  root: string;
  cluster: boolean;
}
export const tenantVault = (t: string): VaultScope => ({ base: `/t/${enc(t)}/vault`, root: t, cluster: false });
export const CLUSTER_VAULT: VaultScope = { base: '/vault', root: 'cluster', cluster: true };
export const vault = (t: string, signal?: AbortSignal, after = '') => vaultList(tenantVault(t), signal, after);
/** 보관함 목록. 클러스터 보관함은 initialized(false면 아직 없음)와 root(뿌리 묶음 ID)가 붙는다. 뿌리 묶음 행은 parent가 "" */
export const vaultList = async (scope: VaultScope, signal?: AbortSignal, after = '') => {
  const r = await api.get<D.ListPage<D.DVault> & { initialized?: boolean; root?: string }>(`${scope.base}${after ? `?after=${enc(after)}` : ''}`, signal);
  return {
    ...page(r, (v): V.SecretView => ({
      realm: v.realm,
      path: v.path,
      kind: v.kind,
      profile: v.profile,
      keys: arr(v.keys),
      group: v.group,
      revision: v.revision,
      id: v.id ?? '',
      parent: v.parent ?? '',
      status: v.status ?? 'active',
      acl: { users: arr(v.acl?.users), services: arr(v.acl?.services), denyUsers: arr(v.acl?.denyUsers), denyServices: arr(v.acl?.denyServices) },
      protected: !!v.protected,
      pendingWrite: v.pendingWrite || undefined,
      maxApprovalAge: v.maxApprovalAge || undefined,
    })),
    initialized: r.initialized,
    root: r.root || undefined,
  };
};
/** 그 객체(묶음이면 아래 비밀값 포함)에서 비밀값을 받는 앱 서비스 */
export const vaultUsages = async (scope: VaultScope, id: string, signal?: AbortSignal): Promise<V.VaultUsage[]> =>
  arr((await api.get<{ items: D.DVaultUsage[] | null }>(`${scope.base}/usages${q({ id })}`, signal)).items).map((u) => ({ ...u, secrets: arr(u.secrets), standalone: u.standalone || undefined }));
export const lifecyclePath = (t: string, name?: string) => `/t/${enc(t)}/lifecycles${name ? `/${enc(name)}` : ''}`;
const toLifecycle = (l: D.DLifecycle): V.LifecycleView => ({ ...l, versions: arr(l.versions).map((v) => ({ ...v, modules: arr(v.modules) })) });
/** 상태 검사 스크립트(이름별로 묶인 버전)와 정책 요약 */
export const lifecycleScripts = async (t: string, signal?: AbortSignal) => {
  const r = await api.get<D.DLifecycleScripts>(`/t/${enc(t)}/lifecycle-scripts`, signal);
  return { items: arr(r.items).map(toLifecycle).sort((a, b) => a.name.localeCompare(b.name)), policy: r.policy };
};
export const lifecycleDetail = async (t: string, name: string, revision: number | undefined, signal?: AbortSignal) => {
  const d = await api.get<D.DLifecycleDetail>(`${lifecyclePath(t, name)}${revision ? `?revision=${revision}` : ''}`, signal);
  return { ...d, script: toLifecycle(d.script), usedBy: d.usedBy ?? undefined };
};
export const lifecyclePolicy = async (t: string, signal?: AbortSignal) => {
  const r = await api.get<{ configured: boolean; policy: D.DLifecyclePolicy }>(`/t/${enc(t)}/lifecycle-policy`, signal);
  const p = r.policy;
  return {
    configured: r.configured,
    policy: {
      ...p,
      build: { ...p.build, nodes: arr(p.build.nodes), targets: arr(p.build.targets) },
      execution: { ...p.execution, capabilities: arr(p.execution.capabilities) },
      resolver: { ...p.resolver, allowPackages: arr(p.resolver.allowPackages), denyPackages: arr(p.resolver.denyPackages), modules: arr(p.resolver.modules) },
    },
  };
};
export const registries = async (t: string, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DRegistry>>(`/t/${enc(t)}/registries`, signal), (r): V.RegistryView => ({
    id: r.id,
    name: r.name,
    endpoint: r.endpoint,
    repositories: r.repositories,
    active: r.active,
    revision: r.revision,
    node: r.node,
    address: r.address,
    certificateID: r.certificateID,
    volume: r.volume,
    // 데몬은 false를 빼고 보낸다(omitempty). 정의가 있는 행(status)이면 없음 = false
    enabled: r.status ? !!r.enabled : r.enabled,
    deleted: r.status ? !!r.deleted : r.deleted,
    status: r.status,
    observedAt: r.observedAt,
    limits: r.limits,
    maintenance: r.maintenance,
  }));
export const registryPath = (t: string, id: string) => `/t/${enc(t)}/registries/${enc(id)}`;
export const imageTrustPath = (t: string) => `/t/${enc(t)}/image-trust`;
export const imageTrust = async (t: string, signal?: AbortSignal) => {
  const r = await api.get<D.DImageTrust>(imageTrustPath(t), signal);
  const uses = (u: D.DTrustUse[] | null) => arr(u).map((x) => ({ ...x, rules: arr(x.rules) }));
  return { ...r, rules: arr(r.rules).map((x) => ({ ...x, uses: uses(x.uses) })), uses: uses(r.uses), untrusted: uses(r.untrusted) };
};
export type ImageTrust = Awaited<ReturnType<typeof imageTrust>>;
export type TrustRule = ImageTrust['rules'][number];
export type TrustUse = ImageTrust['uses'][number];
type PlainRule = { registry: string; repository: string };
const ruleKey = (r: PlainRule) => `${r.registry}/${r.repository}`;
/** 신뢰 출처 바꾸기는 바뀐 규칙만 보낸다(PATCH {add, remove, expected}). before → next 차이 */
export const trustDelta = (before: PlainRule[], next: PlainRule[]) => {
  const had = new Set(before.map(ruleKey));
  const has = new Set(next.map(ruleKey));
  const pick = (r: PlainRule) => ({ registry: r.registry, repository: r.repository });
  return { add: next.filter((r) => !had.has(ruleKey(r))).map(pick), remove: before.filter((r) => !has.has(ruleKey(r))).map(pick) };
};
/** 이 규칙들을 빼면 신뢰를 잃는 곳 */
export const imageTrustPreview = async (t: string, remove: PlainRule[]) =>
  arr((await api.post<{ affected: D.DTrustUse[] | null }>(`${imageTrustPath(t)}/preview`, { remove })).affected);
export const images = async (t: string, signal?: AbortSignal) => page(await api.get<D.ListPage<V.ImageView>>(`/t/${enc(t)}/images`, signal), (x) => x);

// ── 작업 기록 ──
const toApproval = (a: D.DGroupApproval): V.GroupApproval => ({ realm: a.realm, group: a.group, services: arr(a.services), state: a.state });
export const toOp = (o: D.DOp): V.OpView => ({ ...o, target: o.target ?? '', approvals: o.approvals ? o.approvals.map(toApproval) : undefined });

// ── 묶음 승인 (UI-72) ──
const unixIso = (t?: number) => (t ? new Date(t * 1000).toISOString() : undefined);
/** 내 배포가 기다리는 묶음 승인 */
export const pendingApprovals = async (t: string, signal?: AbortSignal): Promise<V.PendingApproval[]> =>
  arr((await api.get<{ items: D.DPendingApproval[] | null }>(`/t/${enc(t)}/vault/approvals`, signal)).items).map((a) => ({
    ...toApproval(a),
    opId: a.opId,
    kind: a.kind === 'build' ? 'build' : a.kind === 'registry-bind' ? 'registry-bind' : a.kind === 'standalone' ? 'standalone' : 'deploy',
    app: a.app ?? '',
    standalone: a.standalone,
    context: a.context,
    build: a.build,
    source: a.source,
    node: a.node,
    updatedAt: a.updatedAt,
  }));
/** 이미 승인된 묶음 사용(철회가 끝난 것은 빠진다, 데몬 #298). collection은 철회의 expected */
export const grantedApprovals = async (t: string, signal?: AbortSignal, app = '', after = '') => {
  const r = await api.get<{ items: D.DGrantedApproval[] | null; next?: string; total?: number; collection: number }>(`/t/${enc(t)}/vault/approvals/granted${q({ app: app || undefined, after: after || undefined })}`, signal);
  return {
    items: arr(r.items).map((g): V.GrantedApproval => ({ ...g, services: arr(g.services), nodes: arr(g.nodes), approvedAt: unixIso(g.approvedAt) ?? '', expiresAt: unixIso(g.expiresAt), revoking: !!g.revoking })),
    next: r.next ?? '',
    total: r.total,
    collection: r.collection,
  };
};
export const deployApprovePath = (t: string, opId: string) => `/t/${enc(t)}/apps/deploy/${enc(opId)}/approve`;
/** 빌드 비밀값 묶음 승인(#226) */
export const buildApprovePath = (t: string, opId: string) => `/t/${enc(t)}/build-approvals/${enc(opId)}/approve`;
export const cdApprovalsPath = (t: string, app: string) => `/t/${enc(t)}/apps/${enc(app)}/cd/approvals`;
/** 자동 배포 상태(UI-40~43, 데몬 #83). CD 앱이 아니면 404 not-cd */
export const cdPath = (t: string, app: string) => `/t/${enc(t)}/apps/${enc(app)}/cd`;
export const appCd = async (t: string, app: string, signal?: AbortSignal) => {
  const r = await api.get<{ app: string; deployment: string; cd: D.DCdState }>(cdPath(t, app), signal);
  return { ...r.cd, overridePaths: arr(r.cd.overridePaths).map((p) => arr(p)) };
};
const pathQ = (path: string[]) => path.map((x) => `path=${encodeURIComponent(x)}`).join('&');
/** 연결하기 전 Git 읽기 확인. 서버가 한 번 읽고 아무것도 바꾸지 않는다. */
export interface CdProbe {
  commit: string;
  size: number;
  node?: string;
}
export const cdProbe = (t: string, app: string, b: { repository: string; branch: string; path: string; credential?: string }) => api.post<CdProbe>(`${cdPath(t, app)}/probe`, b);
/** 후보·실행 이력(최신 순) */
export const cdHistory = async (t: string, app: string, signal?: AbortSignal) => page(await api.get<D.ListPage<D.DCdHistory>>(`${cdPath(t, app)}/history`, signal), (x) => x);
/** 필드의 Git 값·지금 값. 비밀값은 secrets에 selector만 */
export const cdValues = (t: string, app: string, path: string[], signal?: AbortSignal) => api.get<D.DCdValues>(`${cdPath(t, app)}/values?${pathQ(path)}`, signal);
/** 실행 중 → 후보 변경점 */
export const cdChanges = async (t: string, app: string, signal?: AbortSignal) => {
  const r = await api.get<D.DCdChanges>(`${cdPath(t, app)}/changes`, signal);
  return { ...r, services: arr(r.services).map((x) => ({ ...x, fields: arr(x.fields) })), added: arr(r.added), removed: arr(r.removed) };
};
export const cdField = (t: string, app: string, path: string[], signal?: AbortSignal) =>
  api.get<D.DCdField>(`${cdPath(t, app)}/field?${path.map((x) => `path=${encodeURIComponent(x)}`).join('&')}`, signal);
/** 자동 배포 후보가 기다리는 묶음 승인(CD를 등록한 사람만 읽음, 아니면 403) */
/** 웹이 더한 서비스 · 후보 승인·반려 · 승인 담당 */
export const cdLocal = async (t: string, app: string, signal?: AbortSignal) => {
  const r = await api.get<D.DCdLocal>(`${cdPath(t, app)}/local`, signal);
  return { ...r, services: arr(r.services), gitServices: arr(r.gitServices), conflicts: arr(r.conflicts) };
};
export const cdApprovers = async (t: string, app: string, signal?: AbortSignal) => arr((await api.get<{ app: string; approvers: string[] | null }>(`${cdPath(t, app)}/approvers`, signal)).approvers);
export const cdApprovals = async (t: string, app: string, candidate: string, signal?: AbortSignal) =>
  arr((await api.get<{ app: string; approvals: D.DGroupApproval[] | null }>(`${cdApprovalsPath(t, app)}${q({ candidate })}`, signal)).approvals).map(toApproval);
export async function opsList(state?: string, signal?: AbortSignal, children = false): Promise<V.OpView[]> {
  const r = await api.get<D.ListPage<D.DOp> | { items: D.DOp[] }>(`/ops${q({ state, children: children ? 1 : undefined })}`, signal);
  return arr(r.items).map(toOp);
}

// ── 알림 ──
export const toNotification = (n: D.DNotification): V.NotificationView => ({
  id: n.id,
  kind: n.kind,
  severity: n.severity === 'error' || n.severity === 'warning' ? n.severity : 'info',
  tenant: n.tenant || undefined,
  title: n.title,
  text: n.body ?? '',
  at: n.createdAt,
  read: !!n.readAt && !n.readAt.startsWith('0001-'),
  link: n.link || undefined,
  todo: n.action,
});
export async function notifications(signal?: AbortSignal, unreadOnly = false, limit = 100) {
  const r = await api.get<{ items: D.DNotification[] | null; unread: number }>(`/notifications${q({ unread: unreadOnly ? 1 : undefined, limit })}`, signal);
  return { items: arr(r.items).map(toNotification), unread: r.unread };
}
export const markNotificationRead = (id: string) => api.post<null>(`/notifications/${enc(id)}/read`);
export const markAllNotificationsRead = () => api.post<null>('/notifications/read-all');
export const notifyPrefs = (signal?: AbortSignal) => api.get<{ prefs: D.DNotifyPrefs; kinds?: string[] }>('/notify-prefs', signal);
export const putNotifyPrefs = (prefs: D.DNotifyPrefs) => api.put<{ prefs: D.DNotifyPrefs }>('/notify-prefs', { prefs });

// ── 웹 앱 설정 · 설정 변경 기록 ──
export const webSettings = (signal?: AbortSignal) => api.get<D.DSettingsReply>('/system/settings', signal);
/** 공급자 진단 로그 (UI-C1). 시스템 관리자만(아니면 403), 로그가 없는 빌드는 409 not-supported */
export const providerLogState = (signal?: AbortSignal) => api.get<D.DProviderLogState>('/diag/provider-log/state', signal);
export const providerLogEnable = () => api.post<D.DProviderLogEnable>('/diag/provider-log/enable');
export const providerLogDisable = () => api.post<D.DProviderLogState>('/diag/provider-log/disable');
/** tail: 가장 새 n개, after: 그 seq 다음부터(page.next). 항목은 늘 오래된 것부터 */
export const providerLogEntries = async (p: { tail?: number; after?: number; limit?: number }, signal?: AbortSignal) => {
  const r = await api.get<D.DProviderLogPage>(`/diag/provider-log${q(p)}`, signal);
  return { ...r, page: { ...r.page, entries: arr(r.page?.entries) } };
};
export const providerLogDownloadUrl = apiUrl('/diag/provider-log/download');
export const putWebSettings = (settings: D.DWebSettings) => api.put<D.DSettingsReply>('/system/settings', { settings });
export const sealStatus = (signal?: AbortSignal) => api.get<D.DSealStatus>('/system/seal', signal);
export const resetSeal = () => api.post<D.DSealStatus>('/system/seal/reset', { confirm: 'reset' });
export const cancelRestore = () => api.del<null>('/system/restore');
export async function auditLog(tenant: string | undefined, before: string | undefined, signal?: AbortSignal) {
  const r = await api.get<{ items: D.DAudit[] | null; next?: string }>(`/audit${q({ tenant, before, limit: 100 })}`, signal);
  return { items: arr(r.items), next: r.next ?? '' };
}

/** GET /users/{username} */
export const rawUser = (u: string, signal?: AbortSignal) => api.get<D.DUserRecord>(`/users/${enc(u)}`, signal);
const hexBytes = (h?: string) => (h ? (h.match(/../g) ?? []).map((x) => parseInt(x, 16)) : undefined);
/** 있는 계정의 put-user는 계정 자체의 칸(Username·Enabled·SystemAdmin)만 보낸다.
 * 로그인 수단은 add-credential·disable-credential, 동작 범위는 PATCH …/scope로 바꾼다. expected는 계정 revision */
export function putUserPayload(u: { id: string; username: string; enabled: boolean; systemAdmin: boolean }, patch: { Enabled?: boolean; SystemAdmin?: boolean }) {
  return { ID: u.id, Username: u.username, Enabled: patch.Enabled ?? u.enabled, SystemAdmin: patch.SystemAdmin ?? u.systemAdmin };
}

// ── 터미널 결과 ──
/** 끊긴 터미널: exec 상태를 읽는다. 같은 opId로 다시 연결해도 다시 실행하지 않는다. */
export async function execResult(opId: string) {
  const r = await api.post<{ op: D.DOp; exec?: { receipt?: import('./streams').ExecReceiptView; running?: boolean; observedAt?: string } }>(`/ops/${enc(opId)}/result`);
  return { op: toOp(r.op), exec: r.exec };
}

// ── 그래프 편집기 배치 좌표 (웹 bbolt) ──
export type GraphLayout = { v: 1; pos: Record<string, { x: number; y: number }> };
export async function appLayout(tenant: string, app: string, deployment: string, signal?: AbortSignal): Promise<GraphLayout | undefined> {
  const r = await api.get<{ layout: GraphLayout | null }>(`/t/${enc(tenant)}/apps/${enc(app)}/layout${q({ deployment })}`, signal);
  return r.layout && r.layout.v === 1 ? r.layout : undefined;
}
export const putAppLayout = (tenant: string, app: string, deployment: string, layout: GraphLayout) =>
  api.put<null>(`/t/${enc(tenant)}/apps/${enc(app)}/layout${q({ deployment })}`, { layout });

// ── 단독 컨테이너 (REQ-29, UI-3E·3F) ──
export const toStandalone = (t: string, x: D.DStandalone): V.StandaloneView => ({
  ...x,
  tenant: t,
  ownerName: x.ownerName || x.owner,
  state: x.state === 'created' ? 'starting' : x.state === 'missing' ? 'unknown' : x.state,
  expiresAt: unix(x.expiresAt),
  disconnectedAt: unix(x.disconnectedAt),
  endedAt: unix(x.endedAt),
  createdAt: unix(x.createdAt),
  observedAt: unix(x.observedAt),
  importedFrom: x.importedFrom && { ...x.importedFrom, at: unix(x.importedFrom.at) },
});
/** all: 다른 사람의 임시 컨테이너까지(작업 공간 관리자·시스템 관리자) */
export const standaloneList = async (t: string, all: boolean, signal?: AbortSignal) =>
  page(await api.get<D.ListPage<D.DStandalone>>(`/t/${enc(t)}/standalone${q({ all: all ? 1 : undefined })}`, signal), (x) => toStandalone(t, x));
export const standaloneGet = async (t: string, name: string, signal?: AbortSignal) => toStandalone(t, (await api.get<{ item: D.DStandalone }>(`/t/${enc(t)}/standalone/${enc(name)}`, signal)).item);
export async function standalonePlan(t: string, yaml: string): Promise<V.StandalonePlanView> {
  const p = await api.post<D.DStandalonePlan>(`/t/${enc(t)}/standalone/plan`, { yaml, diff: true });
  return {
    name: p.name,
    revision: p.revision,
    create: p.create,
    recreate: p.recreate,
    limits: p.limits,
    changes: arr(p.changes).map((c) => ({ field: c.field, change: c.before === undefined || c.before === null ? 'add' : c.after === undefined || c.after === null ? 'remove' : 'update' })),
    impact: arr(p.impact).map((i) => ({ kind: i.kind, name: i.target, level: i.blocking ? 'block' : 'info', text: i.code && !i.detail.includes(i.code) ? `${i.detail} (${i.code})` : i.detail })),
    diff: p.diff ? parseDiff(p.diff) : [],
  };
}
/** 단독 컨테이너를 컨테이너 상세(로그·자원·프로세스·터미널)가 여는 모양으로 */
export const standaloneTask = (s: V.StandaloneView): V.TaskView => ({
  id: `${s.tenant}/standalone/${s.name}`,
  tenant: s.tenant,
  app: '',
  service: s.name,
  instance: '1',
  node: s.node,
  image: s.image,
  desired: s.state === 'exited' ? 'stopped' : 'running',
  observed: s.state === 'pending' ? 'starting' : s.state === 'removed' ? 'exited' : s.state,
  health: 'none',
  generation: s.revision,
  restarts: s.restarts,
  exitCode: s.exitCode,
  observedAt: s.observedAt ?? new Date(0).toISOString(),
  stale: !s.observedAt,
  standalone: s.name,
});

/** 이미지 참조 확인(REQ-31 image-resolve). 서버 기능이 없으면 404/501 */
export const resolveImage = (t: string, ref: string) => api.post<V.ImageResolveView>(`/t/${enc(t)}/images/resolve`, { ref });

// ── 저장소 이미지와 정리 (UI-84·8A, sfcd 실제 계약 #242) ──
const unixMs = (v: string | number) => (typeof v === 'string' ? Date.parse(v) : v < 1e12 ? v * 1000 : v);
const isDigest = (s: string) => /^sha256:[0-9a-f]{64}$/.test(s);
/** 한 쪽(8행). repository 없이 부르면 repositories, 있으면 그 저장소의 items */
export const registryCatalog = async (t: string, id: string, opts: { external?: boolean; repository?: string; after?: string; refresh?: boolean } = {}, signal?: AbortSignal) => {
  const p = await api.get<D.DCatalogPage>(
    `${registryPath(t, id)}/images${q({ external: opts.external ? 1 : undefined, repository: opts.repository, after: opts.after, refresh: opts.refresh ? 1 : undefined })}`,
    signal,
  );
  return { ...p, repositories: arr(p.repositories), items: arr(p.items), next: p.next ?? '' };
};
/** 이 화면의 이미지 한 개: 같은 저장소·같은 digest의 행을 묶는다(태그 여럿) */
export interface RegistryImage {
  registry: string;
  external: boolean;
  repository: string;
  digest: string;
  tags: string[];
  /** imageBytes */
  bytes: number;
  manifestBytes: number;
  mediaType: string;
  /** Unix ms. sfcd가 모르면(외부 저장소 등) 없음 */
  pushedAt?: number;
}
const groupRows = (id: string, external: boolean, rows: D.DCatalogRow[]): RegistryImage[] => {
  const by = new Map<string, RegistryImage>();
  for (const r of rows) {
    const k = `${r.repository}@${r.digest}`;
    const cur = by.get(k) ?? { registry: id, external, repository: r.repository, digest: r.digest, tags: [], bytes: r.imageBytes, manifestBytes: r.manifestBytes, mediaType: r.mediaType, pushedAt: r.uploadedAt ? Date.parse(r.uploadedAt) : undefined };
    if (!isDigest(r.reference) && !cur.tags.includes(r.reference)) cur.tags.push(r.reference);
    if (r.uploadedAt && !cur.pushedAt) cur.pushedAt = Date.parse(r.uploadedAt);
    by.set(k, cur);
  }
  return [...by.values()];
};
/** 동시에 n개까지 */
async function pool<T, R>(xs: T[], n: number, f: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(xs.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, xs.length) }, async () => {
      while (i < xs.length) {
        const k = i++;
        out[k] = await f(xs[k]);
      }
    }),
  );
  return out;
}
/** 저장소마다 이어 받을 쪽 수 상한(쪽마다 8행). 넘으면 truncated */
const PAGE_CAP = 60;
/**
 * 저장소 이름을 끝까지 받고, 저장소마다 이미지 쪽을 끝까지 이어 받는다. 데몬이 같은 쪽을 10분 동안 기억하므로 다시 읽기는 싸다.
 * code가 있으면 목록을 못 읽은 것이고 행이 없다.
 */
export const registryImagesAll = async (t: string, id: string, opts: { external?: boolean; refresh?: boolean } = {}, signal?: AbortSignal) => {
  const ext = !!opts.external;
  const first = await registryCatalog(t, id, { external: ext, refresh: opts.refresh }, signal);
  const repos = [...first.repositories];
  let next = first.next;
  let truncated = false;
  for (let i = 0; next && !first.code; i++) {
    if (i >= PAGE_CAP) {
      truncated = true;
      break;
    }
    const p = await registryCatalog(t, id, { external: ext, after: next }, signal);
    repos.push(...p.repositories);
    next = p.next;
  }
  let cachedAt = first.cachedAt;
  let live = first.live;
  const repoCodes: Record<string, string> = {};
  const rows = first.code
    ? []
    : (
        await pool(repos, 4, async (repository) => {
          const out: D.DCatalogRow[] = [];
          let after = '';
          for (let i = 0; ; i++) {
            if (i >= PAGE_CAP) {
              truncated = true;
              break;
            }
            const p = await registryCatalog(t, id, { external: ext, repository, after: after || undefined, refresh: opts.refresh }, signal);
            if (p.code) {
              repoCodes[repository] = p.code;
              break;
            }
            if (p.cachedAt < cachedAt) cachedAt = p.cachedAt;
            live = live || p.live;
            out.push(...p.items);
            if (!p.next) break;
            after = p.next;
          }
          return out;
        })
      ).flat();
  return { kind: first.kind, id, external: ext, authority: first.authority, code: first.code, live, repositories: repos, items: groupRows(id, ext, rows), truncated, repoCodes, asOf: first.asOf, cachedAt };
};
export type RegistryImagePage = Awaited<ReturnType<typeof registryImagesAll>>;
/** 한 번에 32개까지라 나눠 묻는다. 응답은 요청 순서 그대로 */
export const imageUsage = async (t: string, refs: string[]) =>
  (
    await pool(
      Array.from({ length: Math.ceil(refs.length / 32) }, (_, i) => refs.slice(i * 32, i * 32 + 32)),
      3,
      async (part) => arr((await api.post<{ items: D.DImageUse[] | null }>(`/t/${enc(t)}/image-usage`, { refs: part })).items),
    )
  )
    .flat()
    .map((u) => ({ ref: u.ref, rows: arr(u.rows), truncated: !!u.truncated, archived: arr(u.archived) }));
export type ImageUse = Awaited<ReturnType<typeof imageUsage>>[number];
/** 삭제·GC·정리 작업의 실제 진행. 웹 작업 ID는 web-<opId> */
export const maintenancePath = (t: string, opId: string) => `/t/${enc(t)}/registry-maintenance/${enc(`web-${opId}`)}`;
export const maintenanceStatus = (t: string, opId: string, signal?: AbortSignal) => api.get<D.DMaintenanceStatus>(maintenancePath(t, opId), signal);
export const prunePreview = async (t: string, id: string, body: { external?: boolean; part: 'items' | 'retained'; conditions: D.DPruneConditions; preview?: string; after?: string }) => {
  const p = await api.post<D.DPrunePage>(`${registryPath(t, id)}/prune/preview`, body);
  return { ...p, rows: arr(p.rows), retainedRows: arr(p.retainedRows), next: p.next ?? '' };
};
export type PrunePage = Awaited<ReturnType<typeof prunePreview>>;
export const pruneResults = async (t: string, opId: string, after?: string, signal?: AbortSignal) => {
  const p = await api.get<D.DPrunePage>(`${maintenancePath(t, opId)}/items${q({ after })}`, signal);
  return { ...p, rows: arr(p.rows), retainedRows: arr(p.retainedRows), next: p.next ?? '' };
};

// ── 외부 저장소 (UI-83, sfcd 실제 계약 #232) ──
export const externalRegistryPath = (t: string, id?: string) => `/t/${enc(t)}/external-registries${id ? `/${enc(id)}` : ''}`;
/** 목록은 한 번에 다 온다(데몬이 끝까지 읽음) */
export const externalRegistries = async (t: string, signal?: AbortSignal) => {
  const p = await api.get<D.ListPage<D.DExternalRegistry>>(externalRegistryPath(t), signal);
  return {
    items: arr(p.items).map((r) => ({ ...r, repository: r.repository || '**', pulls: arr(r.pulls).map((x) => ({ ...x, completedAt: unixMs(x.completedAt), reportedAt: unixMs(x.reportedAt) })) })),
    revision: p.revision ?? 0,
    asOf: p.asOf ?? '',
  };
};
export type ExternalRegistry = Awaited<ReturnType<typeof externalRegistries>>['items'][number];
/** 이 정의로 로그인해 받는 이미지를 쓰는 곳(image-usages). 한 쪽씩 */
export const externalRegistryUsers = async (t: string, id: string, after?: string, signal?: AbortSignal) => {
  const p = await api.get<{ items: D.DExternalRegistryUse[] | null; next?: string }>(`${externalRegistryPath(t, id)}/users${q({ after: after || undefined })}`, signal);
  return { items: arr(p.items), next: p.next || undefined };
};
/** 연결된 서버가 대신 로그인해 본다. 연결된 서버가 없으면 409 not-bound */
export const testExternalRegistry = async (t: string, id: string, image?: string) => {
  const r = await api.post<D.DLoginTest>(`${externalRegistryPath(t, id)}/test`, image ? { image } : {});
  return { ...r, at: unixMs(r.at) ?? Date.now() };
};
export type LoginTest = Awaited<ReturnType<typeof testExternalRegistry>>;
export const externalBindApprovePath = (t: string, source: string, opId: string) => `${externalRegistryPath(t, source)}/bind/${enc(opId)}/approve`;

// ── 이미지 빌드 ──
const allPages = async <T>(path: string, signal?: AbortSignal) => {
  const items: T[] = [];
  let after = '';
  let first: D.ListPage<T> | undefined;
  for (let i = 0; i < 50; i++) {
    const p = await api.get<D.ListPage<T>>(`${path}${path.includes('?') ? q({ after }).replace('?', '&') : q({ after })}`, signal);
    first ??= p;
    items.push(...arr(p.items));
    if (!p.next) break;
    after = p.next;
  }
  return { items, revision: first?.revision ?? 0, asOf: first?.asOf ?? '' };
};
export const buildPath = (t: string, rest = '') => `/t/${enc(t)}${rest}`;
export const contextPath = (t: string, id: string, rest = '') => `/t/${enc(t)}/build-contexts/${enc(id)}${rest}`;
export const buildPolicy = async (t: string, signal?: AbortSignal) => {
  const p = await api.get<D.DBuildPolicy>(buildPath(t, '/build-policy'), signal);
  return { ...p, nodes: arr(p.nodes), platforms: arr(p.platforms), cleanup: p.cleanup ?? { highWaterPercent: 0, unusedDays: 0 } };
};
export type BuildPolicy = Awaited<ReturnType<typeof buildPolicy>>;
const isoMs = (v?: string) => (v ? Date.parse(v) : undefined);
const buildRow = (b: D.DBuild) => ({ ...b, label: `b${b.number}`, createdAt: isoMs(b.createdAt), closedAt: isoMs(b.closedAt), cancel: !!b.cancel });
export type Build = ReturnType<typeof buildRow>;
const versionRow = (v: D.DBuildVersion) => ({ ...v, at: isoMs(v.at) });
export type BuildVersion = ReturnType<typeof versionRow>;
export const buildContexts = async (t: string, signal?: AbortSignal) => {
  const p = await allPages<D.DBuildContext>(buildPath(t, '/build-contexts'), signal);
  return {
    ...p,
    items: p.items.map((c) => ({
      ...c,
      args: c.args ?? {},
      secrets: arr(c.secrets),
      tags: arr(c.tags),
      platforms: arr(c.platforms),
      versions: arr(c.versions).map(versionRow),
      gitCheck: c.gitCheck && { ...c.gitCheck, at: isoMs(c.gitCheck.at) },
      lastBuild: c.lastBuild && buildRow(c.lastBuild),
    })),
  };
};
export type BuildContext = Awaited<ReturnType<typeof buildContexts>>['items'][number];
export const builds = async (t: string, context?: string, signal?: AbortSignal) => {
  const p = await allPages<D.DBuild>(buildPath(t, `/builds${q({ context })}`), signal);
  return { ...p, items: p.items.map(buildRow) };
};
/** 초안(version 0)과 보존 버전 트리를 한 모양으로: 파일만, 폴더 행은 뺀다. dockerfile은 경로 */
export const buildTree = async (t: string, id: string, version?: number, signal?: AbortSignal) => {
  const p = await api.get<D.DBuildTree>(contextPath(t, id, `/tree${q({ version: version || undefined })}`), signal);
  const files = arr(p.entries)
    .filter((e) => !e.directory)
    .map((e) => ({ path: e.path, bytes: e.bytes, executable: e.executable, digest: e.digest }));
  const draft = !p.version;
  return { version: p.version, draft, revision: 'revision' in p ? p.revision : 0, initialized: 'initialized' in p ? p.initialized : true, files, dockerfile: p.dockerfile };
};
export type BuildTree = Awaited<ReturnType<typeof buildTree>>;
export const buildFilePath = (t: string, id: string, path: string, version?: number) => contextPath(t, id, `/file${q({ version: version || undefined, path })}`);
/** 컨텍스트 파일 내용. limits.fileReadBytes보다 크면 413 */
export const buildFileText = (t: string, id: string, path: string, version?: number, signal?: AbortSignal) => api.text(buildFilePath(t, id, path, version), signal);
export const verifyBuildContext = async (t: string, id: string) => {
  const p = await api.post<D.DBuildVerify>(contextPath(t, id, '/verify'), {});
  return { ...p, baseSources: arr(p.baseSources) };
};
/** 바이트 한 쪽. after는 앞 쪽의 next(불투명). after가 'tail'이면 마지막 한 쪽 */
export const buildLog = (t: string, id: string, after?: string, signal?: AbortSignal) =>
  api.get<D.DBuildLog>(buildPath(t, `/builds/${enc(id)}/log${after === 'tail' ? '?tail=1' : q({ after: after || undefined })}`), signal);
export type BuildLog = D.DBuildLog;
const usageRow = (u: D.DBuildCacheUsage) => ({ ...u, observedAt: isoMs(u.observedAt), lastAttemptAt: isoMs(u.lastAttemptAt), kinds: arr(u.kinds) });
export const buildCache = async (t: string, signal?: AbortSignal) => {
  const p = await api.get<D.DBuildCache>(buildPath(t, '/build-cache'), signal);
  return {
    ...p,
    cleanup: p.cleanup ?? { highWaterPercent: 0, unusedDays: 0 },
    nodes: arr(p.nodes),
    caches: arr(p.caches).map((c) => ({ ...c, usage: c.usage && usageRow(c.usage) })),
    cleaning: arr(p.cleaning).map((c) => ({ ...c, acceptedAt: isoMs(c.acceptedAt), closedAt: isoMs(c.closedAt), filter: { ...c.filter, ids: arr(c.filter?.ids) } })),
  };
};
export type BuildCache = Awaited<ReturnType<typeof buildCache>>;
export type BuildCacheScope = BuildCache['caches'][number];
export type BuildCleaning = BuildCache['cleaning'][number];
export const buildCacheEntries = async (t: string, node: string, cache: string, after?: string, signal?: AbortSignal) => {
  const p = await api.get<D.DBuildCacheEntries>(buildPath(t, `/build-cache/entries${q({ node, cache, after: after || undefined })}`), signal);
  return { ...p, observedAt: isoMs(p.observedAt), entries: arr(p.entries).map((e) => ({ ...e, createdAt: isoMs(e.createdAt), lastUsedAt: isoMs(e.lastUsedAt) })) };
};
export type BuildCacheEntries = Awaited<ReturnType<typeof buildCacheEntries>>;
export type BuildCacheEntry = BuildCacheEntries['entries'][number];

// ── 컨테이너 상세와 옮기기 전 검사 ──

/** 앱 Task는 /t/{t}/apps/{app}/task?service=&instance=, 단독 컨테이너는 /t/{t}/standalone/{name}/task */
export interface TaskRef {
  tenant: string;
  app: string;
  service: string;
  instance: string;
  standalone?: string;
}
const taskBase = (r: TaskRef, sub = '') => (r.standalone ? `/t/${enc(r.tenant)}/standalone/${enc(r.standalone)}/task${sub}` : `/t/${enc(r.tenant)}/apps/${enc(r.app)}/task${sub}`);
const taskSel = (r: TaskRef) => (r.standalone ? {} : { service: r.service, instance: r.instance });
export const taskDetail = (r: TaskRef, signal?: AbortSignal) => api.get<D.DTaskDetail>(`${taskBase(r)}${q(taskSel(r))}`, signal);
export const taskHistory = (r: TaskRef, limit = 0, signal?: AbortSignal) => api.get<D.DTaskHistory>(`${taskBase(r, '/history')}${q({ ...taskSel(r), limit: limit || undefined })}`, signal);
export const taskLogs = (r: TaskRef, cursor?: string, limit = 200, signal?: AbortSignal) => api.get<D.DTaskLogPage>(`${taskBase(r, '/logs')}${q({ ...taskSel(r), cursor, limit })}`, signal);
export const taskStats = async (r: TaskRef, signal?: AbortSignal) => arr((await api.get<{ items?: D.DTaskStats[] }>(`${taskBase(r, '/stats')}${q(taskSel(r))}`, signal)).items);
export const restartTaskPath = (tenant: string, app: string) => `/t/${enc(tenant)}/apps/${enc(app)}/task/restart`;
export const relocationCheck = (tenant: string, app: string, service: string, node: string, signal?: AbortSignal) => api.get<D.DRelocationCheck>(`/t/${enc(tenant)}/apps/${enc(app)}/relocation-check${q({ service, node })}`, signal);
/** 컨테이너 상세 화면 주소 */
export const containerPath = (tenant: string, app: string, service: string, instance: string) => `${appPath(tenant, app)}/c/${enc(service)}/${enc(instance)}`;
/** container-observe 로그 단발 읽기. tail은 줄 수, since는 Unix 초 */
export const observeLogs = (r: TaskRef, p: { tail?: number; since?: number; until?: number }) =>
  api.post<D.DObserveLogs>(r.standalone ? `/t/${enc(r.tenant)}/standalone/${enc(r.standalone)}/observe` : `/t/${enc(r.tenant)}/apps/${enc(r.app)}/observe`, { ...(r.standalone ? {} : { service: r.service, instance: r.instance }), kind: 'logs', ...p });
/** 로그 지우기(#761): 앱이나 단독 하나, 앱이면 service·key(작업 키)로 좁힌다 */
export interface LogsSelection {
  app?: string;
  standalone?: string;
  service?: string;
  key?: string;
}
/** 모든 멤버 서버에 바로 보내는 요청(opId·op 없음). 다시 보내도 같은 요청이다 */
export const clearLogs = (tenant: string, s: LogsSelection) => api.post<D.DLogsClear>(`/t/${enc(tenant)}/logs/clear`, s);
/** 서버별 보관소가 지닌 로그 목록(지워진 컨테이너 포함, 줄 내용 없음) */
export const storedLogs = (tenant: string, s: LogsSelection & { node?: string }, signal?: AbortSignal) => api.get<D.DStoredLogs>(`/t/${enc(tenant)}/logs/stored${q({ ...s })}`, signal);

// ── 이미지 올리기·레이어 보기·태그 추가 (UI-88·89) ──
const regBase = (t: string, id: string) => `/t/${enc(t)}/registries/${enc(id)}`;
export const imageManifest = (t: string, id: string, repository: string, ref: string, platform?: string, signal?: AbortSignal) => api.get<D.DImageManifest>(`${regBase(t, id)}/images/manifest${q({ repository, ref, platform })}`, signal);
export const layerFiles = (t: string, id: string, repository: string, digest: string, signal?: AbortSignal) => api.get<D.DLayerFiles>(`${regBase(t, id)}/images/layer${q({ repository, digest })}`, signal);
export const addImageTag = (t: string, id: string, body: { repository: string; digest: string; tag: string; overwrite?: boolean }) => api.post<{ repository: string; tag: string; digest: string }>(`${regBase(t, id)}/images/tag`, body);
export const uploadsPath = (t: string, id: string) => `${regBase(t, id)}/uploads`;
export const imageUploads = async (t: string, id: string, signal?: AbortSignal) => arr((await api.get<{ items?: D.DImageUpload[] }>(uploadsPath(t, id), signal)).items);
export const imageUpload = (t: string, id: string, uid: string, signal?: AbortSignal) => api.get<D.DImageUpload>(`${uploadsPath(t, id)}/${enc(uid)}`, signal);
export const startImageUpload = (t: string, id: string, fileName: string, bytes: number) => api.post<D.DImageUpload>(uploadsPath(t, id), { fileName, bytes });
export const putUploadChunk = (t: string, id: string, uid: string, n: number, blob: Blob) => api.raw<{ received: number; missing: number[] }>('PUT', `${uploadsPath(t, id)}/${enc(uid)}/chunks/${n}`, blob);
export const inspectUpload = (t: string, id: string, uid: string) => api.post<unknown>(`${uploadsPath(t, id)}/${enc(uid)}/inspect`, {});
export const pushUpload = (t: string, id: string, uid: string, body: { item: number; repository: string; tag: string; overwrite?: boolean }) => api.post<D.DImageUpload>(`${uploadsPath(t, id)}/${enc(uid)}/push`, body);
export const deleteUpload = (t: string, id: string, uid: string) => api.del<unknown>(`${uploadsPath(t, id)}/${enc(uid)}`);

// ── 웹 데이터 자동 백업 ──
/** account는 계정 이름(#119), accountId는 첫 로그인 뒤 채워짐(#122). 비면 위임할 때 이름으로 찾는다 */
export type AutoBackupView = Omit<D.DAutoBackup, 'account'> & { account?: { id: string; username: string } };
export const autoBackup = async (signal?: AbortSignal): Promise<AutoBackupView> => {
  const r = await api.get<D.DAutoBackup>('/system/auto-backup', signal);
  const { accountId, ...rest } = r;
  return { ...rest, account: typeof r.account === 'string' ? { id: accountId ?? '', username: r.account } : r.account };
};
/** 폴더 위임(file-grants)은 user ID를 받는다. 계정 이름으로 찾는다 */
export const userIdOf = async (username: string) => {
  const u = (await users()).items.find((x) => x.username === username);
  if (!u) throw new Error(`자동 작업 계정 ${username}을 사용자 목록에서 찾지 못했습니다.`);
  return u.id;
};
export const putAutoBackup = (b: { enabled: boolean; at: string; keep: number; tenant: string; volume: string }) => api.put<D.DAutoBackup>('/system/auto-backup', b);
export const runAutoBackup = () => api.post<{ running: boolean }>('/system/auto-backup/run', {});
export const restoreFrom = (b: { tenant: string; volume: string; path: string }) => api.post<{ restorePending: boolean; bytes: number }>('/system/restore-from', b);
/** 데이터 저장소 안 파일 목록(접두어 아래, 끝까지 이어 받음) */
export const volumeFiles = async (t: string, name: string, prefix: string, signal?: AbortSignal) => {
  const items: D.DVolumeFile[] = [];
  let after = '';
  for (let i = 0; i < 50; i++) {
    const p = await api.get<{ items: D.DVolumeFile[] | null; next?: string }>(`${volumePath(t, name)}/files${q({ prefix, after })}`, signal);
    items.push(...arr(p.items));
    if (!p.next) break;
    after = p.next;
  }
  return items;
};
export const volumeFileUrl = (t: string, name: string, path: string) => apiUrl(`${volumePath(t, name)}/file${q({ path })}`);
export const volumeFilePath = (t: string, name: string) => `${volumePath(t, name)}/file`;
export const fileGrantsPath = (t: string, name: string) => `${volumePath(t, name)}/file-grants`;

/** 계정 동작 범위. actions가 비면 제한 없음. u는 사용자 ID */
/** revision은 계정 revision(#461)이라 0이 아니다. PATCH expected에 그대로 쓴다 */
export type AccountScope = { user: string; actions: string[]; keyOnly: boolean; revision: number };
export const accountScope = async (u: string, signal?: AbortSignal): Promise<AccountScope> => {
  const r = await api.get<AccountScope>(`/users/${enc(u)}/scope`, signal);
  return { ...r, actions: arr(r.actions) };
};
/** 같은 동작 목록인지(서버는 정렬해 돌려주므로 순서는 보지 않는다) */
export const sameActions = (a: string[], b: string[]) => [...a].sort().join(',') === [...b].sort().join(',');
export const accountScopePath = (u: string) => `/users/${enc(u)}/scope`;
/** PATCH …/scope 본문: 읽은 범위 cur에서 actions·keyOnly로 가는 변경분. 목록 전체는 보내지 않는다.
 * actions가 비면 제한을 푼다(unlimited). 바뀐 것이 없으면 undefined */
export function scopeDelta(cur: AccountScope, actions: string[], keyOnly: boolean) {
  const add = actions.filter((a) => !cur.actions.includes(a));
  const remove = cur.actions.filter((a) => !actions.includes(a));
  const body: { expected: number; add?: string[]; remove?: string[]; unlimited?: boolean; keyOnly?: boolean } = { expected: cur.revision };
  if (!actions.length && cur.actions.length) body.unlimited = true;
  else {
    if (add.length) body.add = add;
    if (remove.length) body.remove = remove;
  }
  if (keyOnly !== cur.keyOnly) body.keyOnly = keyOnly;
  return Object.keys(body).length > 1 ? body : undefined;
}

// ── 자동 작업 계정 (REQ-9, 웹 데몬) ──
/** 개인키는 웹 봉인 파일에만 있고 여기에는 공개키·지문만 온다 */
export type AutomationView = {
  configured: boolean;
  sealReady: boolean;
  username?: string;
  userId?: string;
  publicKey?: string;
  fingerprint?: string;
  createdBy?: string;
  createdAt?: string;
  lastCheck?: { at: string; ok: boolean; user?: string; error?: string; reason?: string };
};
export type AutomationCheck = { ok: boolean; user?: string; username?: string; systemAdmin?: boolean; error?: string };
export const automation = (signal?: AbortSignal) => api.get<AutomationView>('/system/automation', signal);
export const putAutomation = (username: string, rotate?: boolean) => api.put<AutomationView>('/system/automation', { username, ...(rotate ? { rotate } : {}) });
export const checkAutomation = () => api.post<AutomationCheck>('/system/automation/check', {});
export const deleteAutomation = () => api.del<void>('/system/automation');
/** 공개키 로그인 수단을 더하는 add-credential 페이로드(관리자가 다른 계정에 더하므로 증명 없음). 이미 같은 키가 있으면 undefined */
export function withAutomationKey(u: D.DUserRecord, publicKey: string) {
  const creds = arr(u.credentials);
  if (creds.some((c) => c.publicKey?.toLowerCase() === publicKey.toLowerCase())) return undefined;
  const ids = new Set(creds.map((c) => c.id));
  let id = 'web-auto';
  for (let n = 2; ids.has(id); n++) id = `web-auto-${n}`;
  return { id, payload: { User: u.id, Credential: { ID: id, Method: 'private-key', PublicKey: hexBytes(publicKey) } } };
}

// ── 서버 고급 동작. 계획을 읽고 그 plan을 그대로 보낸다(바뀌면 409 plan-changed) ──
// operation은 처음엔 비워 두고, 계획이 돌려준 operation을 다시 읽을 때와 보낼 때 그대로 쓴다.
const opQ = (operation?: string) => (operation ? `?${new URLSearchParams({ operation })}` : '');
export const nodeDrainPlan = async (node: string, signal?: AbortSignal, operation?: string) => {
  const r = await api.get<D.DNodeDrainPlan>(`/nodes/${enc(node)}/drain-plan${opQ(operation)}`, signal);
  return { ...r, tasks: arr(r.tasks), blockers: arr(r.blockers), jobs: arr(r.jobs) };
};
/** operation을 빼면 이 웹에서 그 서버에 보낸 마지막 비우기(없으면 404, 데몬 #338) */
export const nodeDrainStatus = async (node: string, operation?: string, signal?: AbortSignal) => {
  const r = await api.get<D.DNodeDrainStatus>(`/nodes/${enc(node)}/drain-status${opQ(operation)}`, signal);
  return { ...r, jobs: arr(r.jobs) };
};
export const nodeVoterPlan = async (node: string, signal?: AbortSignal) => {
  const r = await api.get<D.DNodeVoterPlan>(`/nodes/${enc(node)}/voter-plan`, signal);
  return { ...r, blockers: arr(r.blockers) };
};
export const nodeForceRemovePlan = async (node: string, signal?: AbortSignal, operation?: string): Promise<NodeForceRemovePlan> =>
  normRemovePlan(await api.get<NodeForceRemovePlan>(`/nodes/${enc(node)}/force-remove-plan${opQ(operation)}`, signal)) as NodeForceRemovePlan;
export const nodeActionPath = (node: string, action: 'drain' | 'demote' | 'rotate-identity' | 'force-remove') => `/nodes/${enc(node)}/${action}`;
export const nodeDiagnosticsUrl = (node: string) => `/api/v1/nodes/${enc(node)}/diagnostics`;

// ── 빌드 컨텍스트 zip 조각 올리기 ──
export type ZipUploadView = { upload: string; context: string; length: number; digest: string; revision: number; partBytes: number; chunkBytes: number; chunks: number; missingChunks: number[] | null; complete: boolean; expiresAt?: string };
export const zipUploadsPath = (t: string, id: string) => contextPath(t, id, '/zip-uploads');
export const zipUpload = (t: string, id: string, upload: string, signal?: AbortSignal) => api.get<ZipUploadView>(`${zipUploadsPath(t, id)}/${enc(upload)}`, signal);
export const putZipChunk = (t: string, id: string, upload: string, n: number, blob: Blob) => api.raw<ZipUploadView>('PUT', `${zipUploadsPath(t, id)}/${enc(upload)}/chunks/${n}`, blob);

// ── 합의 로그 수동 압축 ──
export interface RaftCompactNode {
  node: string;
  state: 'queued' | 'running' | 'done' | 'failed' | 'skipped';
  snapshotIndex?: number;
  snapshotBytes?: number;
  logBytesBefore?: number;
  logBytesAfter?: number;
  durationMs?: number;
  error?: string;
}
export interface RaftCompactRun {
  /** sfcd 작업 이름. 웹에서 보냈으면 op-<opId> (데몬 #387) */
  operation?: string;
  /** 이 웹에서 보낸 압축일 때만 있다 */
  id?: string;
  at: string;
  by: string;
  mode: 'keep' | 'minimal';
  state: 'running' | 'done' | 'failed';
  nodes: RaftCompactNode[];
}
export interface RaftCompactView {
  /** 스냅샷 뒤에 남기는 로그 건수(설정값) */
  retain: number;
  /** minimal에서 남기는 건수 */
  minimal: number;
  /** 서버마다 스냅샷 뒤 로그 건수 */
  entries: Record<string, number>;
  last?: RaftCompactRun;
}
/** SFCP 기능 표·서버별 알린 기능·클러스터 교집합 (UI-17) */
export const clusterFeatures = (signal?: AbortSignal) => api.get<D.DClusterFeatures>('/cluster/features', signal);
export const raftCompact = (signal?: AbortSignal) => api.get<RaftCompactView>('/raft/compact', signal);
/** 압축 미리보기 (데몬 #387). 수락 때 sfcd가 다시 검사한다 */
export interface RaftCompactPlan {
  mode: 'keep' | 'minimal';
  retain?: number;
  parallel: boolean;
  total: number;
  /** 실행 순서. 리더가 마지막 */
  nodes: string[];
  /** 미리보기 digest(64 hex, 데몬 #391). POST에 그대로 실어 보면 대상이 바뀐 걸 409 plan-changed로 안다 */
  plan: string;
}
export const raftCompactPlan = async (nodes: string[], mode: 'keep' | 'minimal', serial: boolean, signal?: AbortSignal): Promise<RaftCompactPlan> => {
  const r = await api.get<RaftCompactPlan>(`/raft/compact/plan?${new URLSearchParams({ nodes: nodes.join(','), mode, serial: String(serial) })}`, signal);
  return { ...r, nodes: arr(r.nodes) };
};
/** 한 압축 작업의 권위 있는 진행 (데몬 #387). snapshot·로그 수치는 GET /raft/compact에 있다 */
export interface RaftCompaction {
  operation: string;
  by?: string;
  at?: string;
  mode: 'keep' | 'minimal';
  retain?: number;
  sequential?: boolean;
  complete: boolean;
  total: number;
  queued: number;
  running: number;
  done: number;
  failed: number;
  skipped: number;
  nodes: { node: string; state: RaftCompactNode['state'] | string; code?: string; revision?: number }[];
}
export const raftCompaction = async (operation: string, signal?: AbortSignal): Promise<RaftCompaction> => {
  const r = await api.get<RaftCompaction>(`/raft/compactions/${enc(operation)}`, signal);
  return { ...r, nodes: arr(r.nodes) };
};

// ── 관리 변경 (UI-A1) ──
export const opActions = async (signal?: AbortSignal) => arr((await api.get<{ items: D.DOpAction[] | null }>('/ops/actions', signal)).items).map((a) => ({ ...a, fields: arr(a.fields) }));
export const opActionBase = (action: string, payload: unknown) => api.post<D.DOpBase>(`/ops/actions/${enc(action)}/base`, { payload });
export const opGet = async (id: string, signal?: AbortSignal) => toOp((await api.get<{ op: D.DOp }>(`/ops/${enc(id)}`, signal)).op);

/** 망 관리 DNS가 답하는 이름과 서버별 반영 상태 (docs/reference/web-api/50-network-dns-names.md) */
export interface NetworkDnsNames {
  managed: boolean;
  enabled: boolean;
  revision: number;
  zone?: string;
  names: { name: string; app: string; service: string; task?: string; family: 'ipv4' | 'ipv6' | string; address: string }[];
  /** 직접 더한 레코드(#631·#636, 바꿀 때는 PATCH …/dns/records로 변경분만). value는 zone 파일 형식 정규형, ttl은 레코드에 정한 TTL(없으면 망의 TTL). served=false면 같은 이름을 앱 서비스가 가져 쉬는 중 */
  records: DnsRecord[];
  servers: { node: string; state: 'ready' | 'not-ready' | 'unreachable' | 'unknown' | string; ready?: boolean; resolvers: string[] }[];
}

export const dnsRecordsPath = (t: string, name: string) => `/t/${enc(t)}/networks/${enc(name)}/dns/records`;
export const networkDnsNames = (t: string, name: string, signal?: AbortSignal) =>
  api.get<NetworkDnsNames>(`/t/${enc(t)}/networks/${enc(name)}/dns/names`, signal).then((r) => ({ ...r, names: arr(r.names), records: arr(r.records), servers: arr(r.servers).map((x) => ({ ...x, resolvers: arr(x.resolvers) })) }));

/** 작업 공간 하나 (GET /tenants/{t}): 실시간 반영이 바뀐 작업 공간만 다시 읽을 때 */
export const tenantOne = (t: string, signal?: AbortSignal) => api.get<V.TenantAccess>(`/tenants/${enc(t)}`, signal);
