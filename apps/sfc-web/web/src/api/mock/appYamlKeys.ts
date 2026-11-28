// SPDX-License-Identifier: Apache-2.0

// app.yaml 형식 검사(목업). 서버 파서(yaml-formats.md)와 같은 거절을 낸다.

/** 새 형식에서 없어진 키를 쓰면 그 안내(데몬 파서와 같은 거절). 문제 없으면 '' */
export function appYamlOldKeys(doc: Record<string, unknown>): string {
  for (const [n, v] of Object.entries((doc.services ?? {}) as Record<string, Record<string, unknown> | null>)) {
    const x = (v?.['x-sfc'] ?? {}) as Record<string, unknown>;
    if ('readiness' in x) return `services.${n}.x-sfc.readiness: ready로 바뀌었습니다(ready: {http: /readyz, port: 8080} 또는 ready: healthcheck).`;
    // yaml-formats.md(D1, #894): x-sfc.secrets {from, env, socket}. 옛 키는 모르는 키(INVALID_FIELD)
    for (const k of ['secret_sources', 'secrets_from', 'secret_env']) if (k in x) return `services.${n}.x-sfc.${k}: 받지 않는 키입니다. x-sfc.secrets {from, env, socket}을 쓰세요.`;
    const sec = x.secrets as Record<string, unknown> | undefined;
    if (sec !== undefined) {
      if (!sec || typeof sec !== 'object' || Array.isArray(sec)) return `services.${n}.x-sfc.secrets: from·env·socket 블록이어야 합니다.`;
      const unknownKey = Object.keys(sec).find((k) => !['from', 'env', 'socket'].includes(k));
      if (unknownKey) return `services.${n}.x-sfc.secrets.${unknownKey}: 받지 않는 키입니다(from, env, socket만).`;
      // [cluster/][group/]이름. 이름은 소문자로 시작하는 a-z·0-9·- 1~63자라 '/'가 들어갈 수 없다
      const ref = (e: unknown) => /^(cluster\/)?(group\/)?[a-z][a-z0-9-]{0,62}$/.test(String(e));
      const from = sec.from;
      if (from !== undefined) {
        if (!Array.isArray(from)) return `services.${n}.x-sfc.secrets.from: 문자열 목록이어야 합니다.`;
        const bad = from.find((e) => !ref(e));
        if (bad !== undefined) return `services.${n}.x-sfc.secrets.from: ${String(bad)}은(는) [cluster/][group/]이름 꼴이 아닙니다.`;
      }
      // sfev.sock은 아직 열지 않는다: 값이 있으면 거절(서버와 같음)
      if (Array.isArray(sec.socket) ? sec.socket.length > 0 : sec.socket != null) return `services.${n}.x-sfc.secrets.socket: 아직 받지 않는 키입니다.`;
      if (sec.env !== undefined && (!Array.isArray(sec.env) || sec.env.some((e) => !e || typeof e !== 'object' || !ref((e as Record<string, unknown>).source) || !(e as Record<string, unknown>).name)))
        return `services.${n}.x-sfc.secrets.env: {source, name} 목록이어야 합니다.`;
    }
  }
  const xs = (doc['x-sfc'] ?? {}) as Record<string, unknown>;
  // Y9: 클러스터 설정 키는 app.yaml에 없다
  const clusterKey = ['nodes', 'vault', 'routing', 'registries'].find((k) => k in xs);
  if (clusterKey) return `x-sfc.${clusterKey}: 받지 않는 키입니다. 클러스터 설정은 클러스터 설정 파일로 정합니다.`;
  for (const [n, v] of Object.entries((doc.networks ?? {}) as Record<string, Record<string, unknown> | null>))
    for (const k of ['driver', 'x-sfc']) if (v && k in v) return `networks.${n}.${k}: 받지 않는 키입니다. 망은 작업 공간의 공유 자원을 이름으로 씁니다.`;
  // A3'(yaml-formats): CD는 x-sfc.cd {repository, branch, path, credential?, poll?, sync, drift, prune}. 옛 delivery는 INVALID_FIELD
  if ('delivery' in xs) return 'x-sfc.delivery: 받지 않는 키입니다. 자동 배포는 x-sfc.cd {repository, branch, path, …}로 씁니다.';
  if (xs.cd !== undefined) {
    const msg = cdProblem(xs.cd);
    if (msg) return msg;
  }
  // A2(#910): x-sfc.ingress는 route 목록. 모든 route는 같은 서버(INGRESS_NODE_MIXED), id는 겹치지 않는다
  if (xs.ingress !== undefined) {
    const msg = ingressListProblem(xs.ingress, 'x-sfc.ingress', ['id', 'node', 'host', 'prefix', 'service', 'port', 'network', 'health', 'gateway', 'balance']);
    if (msg) return msg;
  }
  const allow: [string, string[]][] = [['volumes', ['node', 'size', 'uid', 'gid', 'mode']], ['secrets', ['key']]];
  for (const [kind, keys] of allow)
    for (const [n, v] of Object.entries((doc[kind] ?? {}) as Record<string, Record<string, unknown> | null>)) {
      const bad = Object.keys((v?.['x-sfc'] ?? {}) as Record<string, unknown>).find((k) => !keys.includes(k));
      if (bad) return `${kind}.${n}.x-sfc.${bad}: 받지 않는 키입니다(${keys.join(', ')}만).${bad === 'capacity_bytes' ? ' 용량은 size(예: 2GiB)로 쓰세요.' : ''}`;
    }
  return '';
}

/** x-sfc.ingress route 목록 검사(서버 deployment ingress_yaml.go와 같은 거절). 문제 없으면 '' */
export function ingressListProblem(ing: unknown, at: string, keys: string[]): string {
  if (!Array.isArray(ing) || ing.length === 0) return `${at}: route 목록이어야 합니다(- {node, host, prefix, …}).`;
  const node = (ing[0] as Record<string, unknown> | null)?.node;
  const ids = new Set<string>();
  for (const [i, x] of ing.entries()) {
    const r = (x ?? {}) as Record<string, unknown>;
    const bad = Object.keys(r).find((k) => !keys.includes(k));
    if (bad) return `${at}[${i}].${bad}: 받지 않는 키입니다.`;
    if (!r.node) return `${at}[${i}].node: 이 route를 여는 서버를 적어야 합니다.`;
    if (r.node !== node) return `${at}[${i}].node: 모든 route는 같은 서버에서 엽니다(INGRESS_NODE_MIXED).`;
    const id = r.id === undefined ? `route-${i + 1}` : String(r.id);
    if (ids.has(id)) return `${at}[${i}].id: ${id}가 겹칩니다.`;
    ids.add(id);
    if (r.gateway !== undefined && r.gateway !== 'external' && r.gateway !== 'local') return `${at}[${i}].gateway: external 또는 local입니다.`;
    const bal = r.balance as Record<string, unknown> | undefined;
    if (bal && typeof bal === 'object') for (const k of ['slow_start', 'slow_start_ms']) if (k in bal) return `${at}[${i}].balance.${k}: 받지 않는 키입니다. warmup(예: 30s)을 쓰세요.`;
  }
  return '';
}

const CD_KEYS = ['repository', 'branch', 'path', 'credential', 'poll', 'sync', 'drift', 'prune'];
/** x-sfc.cd 검사(INVALID_CD). 문제 없으면 '' */
export function cdProblem(cd: unknown): string {
  if (!cd || typeof cd !== 'object' || Array.isArray(cd)) return 'x-sfc.cd: repository·branch·path를 가진 블록이어야 합니다.';
  const c = cd as Record<string, unknown>;
  const bad = Object.keys(c).find((k) => !CD_KEYS.includes(k));
  if (bad) return `x-sfc.cd.${bad}: 받지 않는 키입니다(${CD_KEYS.join(', ')}만).`;
  for (const k of ['repository', 'branch', 'path']) if (typeof c[k] !== 'string' || !c[k]) return `x-sfc.cd.${k}: 꼭 적어야 합니다.`;
  if (c.credential !== undefined && typeof c.credential !== 'string') return 'x-sfc.cd.credential: 자격 증명 이름(문자열)이어야 합니다.';
  if (c.poll !== undefined) {
    const sec = typeof c.poll === 'string' ? goDurationSeconds(c.poll) : undefined;
    if (sec === undefined) return 'x-sfc.cd.poll: 30s·1m·1h30m 꼴이어야 합니다(없으면 1m).';
    if (sec < 1 || sec > 86400) return 'x-sfc.cd.poll: 1s 이상 24h 이하여야 합니다.';
    if (Math.abs(sec - Math.round(sec)) > 1e-9) return 'x-sfc.cd.poll: 초 단위로 떨어져야 합니다(1.5s는 안 됨).';
  }
  if (c.sync !== undefined && c.sync !== 'manual' && c.sync !== 'auto') return 'x-sfc.cd.sync: manual 또는 auto입니다.';
  if (c.drift !== undefined && c.drift !== 'report' && c.drift !== 'reconcile') return 'x-sfc.cd.drift: report 또는 reconcile입니다.';
  if (c.prune !== undefined && typeof c.prune !== 'boolean') return 'x-sfc.cd.prune: true 또는 false입니다.';
  return '';
}

/** Go time.ParseDuration 꼴(1h30m, 500ms, 1.5s)을 초로. 못 읽으면 undefined */
export function goDurationSeconds(v: string): number | undefined {
  if (!/^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(v)) return undefined;
  const unit: Record<string, number> = { ns: 1e-9, us: 1e-6, µs: 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };
  let total = 0;
  for (const m of v.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)) total += Number(m[1]) * unit[m[2]];
  return total;
}
