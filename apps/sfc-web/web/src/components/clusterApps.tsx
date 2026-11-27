// SPDX-License-Identifier: Apache-2.0

// 클러스터 앱(cluster app) 표시 조각: 서버 상세 카드(UI-12)와 서버 › 클러스터 앱(UI-12A)이 함께 쓴다.
import type { DClusterApp } from '../api/dto';
import type { Tone } from './ui';

export const CLUSTER_APP_STATE: Record<string, [Tone, string]> = {
  starting: ['pr', '시작 중'],
  running: ['ok', '실행 중'],
  restarting: ['wa', '재시작 중'],
  stopping: ['pr', '멈추는 중'],
  exited: ['er', '종료됨'],
  failed: ['er', '실패'],
  'image-not-found': ['er', '이미지 없음'],
  'image-mismatch': ['er', '이미지 불일치'],
  refused: ['er', '거부됨'],
};
export const CLUSTER_APP_REASON: Record<string, string> = {
  'image-not-installed': '클러스터 앱 이미지 패키지가 설치되지 않았습니다',
  'release-unverified': '이미지 릴리스 정보에 믿을 수 있는 서명이 없습니다',
  'image-digest-mismatch': '설치된 이미지가 릴리스 정보에 적힌 이미지와 다릅니다',
  'image-load-failed': '클러스터 앱 이미지를 불러오지 못했습니다',
  'reconcile-failed': '컨테이너를 띄우거나 맞추지 못했습니다',
  'status-unavailable': '컨테이너 상태를 읽지 못했습니다',
  'port-unavailable': 'node.yaml의 포트를 열지 못했습니다',
  'address-unavailable': '클러스터 공용 주소를 컨테이너에 넘기지 못했습니다',
  'system-network-pending': '이 서버의 시스템 망이 아직 준비되지 않았습니다. 원인은 서버의 sfcd 로그에 있습니다',
};
/** 거부됨이면 '이미 node-a에서 실행 중' 글(서버 이름은 링크로 그린다) */
export const refusedBy = (a: Pick<DClusterApp, 'state' | 'runningOn'>) => (a.state === 'refused' ? a.runningOn : undefined);
/** 클러스터 앱 설명. 웹 앱은 지금 보는 이 화면 */
export const clusterAppNote = (name: string) => (name === 'web' || name === 'sfc-web' ? 'sfc-web · 웹 앱 · 지금 보는 이 화면' : undefined);
export const shortDigest = (d: string) => {
  const [alg, hex = ''] = d.split(':');
  return hex.length > 8 ? `${alg}:${hex.slice(0, 4)}…${hex.slice(-2)}` : d;
};

/** 포트 이름: web은 숫자만, direct는 '직접 접속', acme는 '응답기', 그 밖은 이름 그대로. 순서도 이대로(모르는 이름은 뒤에) */
const PORT_NAME: Record<string, string> = { web: '', direct: '직접 접속', acme: '응답기' };
const PORT_ORDER = Object.keys(PORT_NAME);
export const portRank = (name: string) => (PORT_ORDER.includes(name) ? PORT_ORDER.indexOf(name) : PORT_ORDER.length);
export function ClusterAppAddress({ a }: { a: DClusterApp }) {
  const parts = [
    ...(a.address ? [<span key="ip" className="mono">{a.address}</span>] : []),
    ...[...(a.ports ?? [])].sort((x, y) => portRank(x.name) - portRank(y.name)).map((p) => {
      const n = PORT_NAME[p.name] ?? p.name;
      return (
        <span key={`${p.name}/${p.port}`}>
          {n ? `${n} ` : ''}
          <span className="mono">
            :{p.port}
            {p.protocol && p.protocol !== 'tcp' ? `/${p.protocol}` : ''}
          </span>
        </span>
      );
    }),
  ];
  return (
    <>
      시스템 망 안
      {parts.map((x, i) => (
        <span key={i}> · {x}</span>
      ))}
    </>
  );
}


/** 이미지 칸: 이름·버전, 고정 digest */
export function ClusterAppImage({ a }: { a: DClusterApp }) {
  return (
    <span className="col" style={{ gap: 2 }}>
      <span className="mono">
        {a.image}
        {a.version ? ` ${a.version}` : ''}
      </span>
      {a.digest && (
        <span className="mono muted" style={{ fontSize: 11 }} title={a.digest}>
          {shortDigest(a.digest)} · sfcd에 고정
        </span>
      )}
    </span>
  );
}
