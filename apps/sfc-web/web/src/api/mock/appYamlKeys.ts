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
  // warmup(예: 30s)이 slow_start·slow_start_ms를 대신한다
  const ing = xs.ingress as Record<string, unknown> | undefined;
  const rs = Array.isArray(ing) ? ing : Array.isArray(ing?.routes) ? (ing.routes as unknown[]) : [];
  for (const r of rs) {
    const bal = (r as Record<string, unknown> | null)?.balance as Record<string, unknown> | undefined;
    if (bal && typeof bal === 'object') for (const k of ['slow_start', 'slow_start_ms']) if (k in bal) return `x-sfc.ingress 경로의 balance.${k}: 받지 않는 키입니다. warmup(예: 30s)을 쓰세요.`;
  }
  const allow: [string, string[]][] = [['volumes', ['node', 'size', 'uid', 'gid', 'mode']], ['secrets', ['key']]];
  for (const [kind, keys] of allow)
    for (const [n, v] of Object.entries((doc[kind] ?? {}) as Record<string, Record<string, unknown> | null>)) {
      const bad = Object.keys((v?.['x-sfc'] ?? {}) as Record<string, unknown>).find((k) => !keys.includes(k));
      if (bad) return `${kind}.${n}.x-sfc.${bad}: 받지 않는 키입니다(${keys.join(', ')}만).${bad === 'capacity_bytes' ? ' 용량은 size(예: 2GiB)로 쓰세요.' : ''}`;
    }
  return '';
}
