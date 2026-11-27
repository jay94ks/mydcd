// SPDX-License-Identifier: Apache-2.0

// 대시보드 시작하기 카드 (캔버스 v224 StartSearch UI-10A). 시스템 관리자에게만 보이고, 각 단계는 실제 상태를 읽어 저절로 체크된다.
// 모두 끝나거나 숨기면 사라진다(내 계정 › 화면 설정에서 다시 켬).
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { myCredentials, networks, tenantList } from '../api/endpoints';
import { ingress } from '../api/ingress';
import type { DashboardView } from '../api/types';
import { useSession } from '../auth/session';
import { applyPrefs, loadPrefs, prefHideStart, savePrefs } from '../lib/uiPrefs';
import { useToast } from '../components/Toast';

interface Step {
  done: boolean;
  title: string;
  sub: string;
  to: string;
  action: string;
}
interface Facts {
  key?: string;
  tenants?: number;
  networks?: number;
  hosts?: number;
}

/** 대시보드 값과 따로 읽은 값으로 단계를 만든다 */
export function startSteps(v: Pick<DashboardView, 'nodes' | 'apps'>, f: Facts): Step[] {
  const ready = v.nodes.filter((n) => n.phase === 'ready');
  const voters = v.nodes.filter((n) => n.voter).length;
  return [
    { done: ready.length > 0, title: `서버 ${v.nodes.length}대 · 투표 서버 ${voters}`, sub: ready.length ? '클러스터가 준비됐습니다' : '준비된 서버가 아직 없습니다', to: '/servers', action: '서버' },
    { done: !!f.key, title: '관리자 키 등록', sub: f.key ?? '이 브라우저에 키를 만들어 내 계정에 등록', to: '/account', action: '키 만들기' },
    { done: (f.tenants ?? 0) > 0, title: '작업 공간 만들기', sub: '앱·망·데이터 저장소를 묶는 단위', to: '/system/tenants?new=1', action: '만들기' },
    { done: (f.networks ?? 0) > 0, title: '망 만들기', sub: '앱이 서로를 이름으로 찾는 망', to: '/shared/networks', action: '망' },
    { done: v.apps.length > 0, title: '첫 앱 배포', sub: 'app.yaml 올리기 또는 폼', to: '/deploy/new', action: '배포' },
    { done: (f.hosts ?? 0) > 0, title: '외부 접속 열기', sub: '도메인 연결 · 인증서 · 경로', to: '/shared/ingress', action: '외부 접속' },
  ];
}

export function StartCard({ v }: { v: DashboardView }) {
  const session = useSession();
  const toast = useToast();
  const [hidden, setHidden] = useState(prefHideStart());
  const [f, setF] = useState<Facts>({});
  const admin = session.user.systemAdmin;
  useEffect(() => {
    if (!admin) return;
    const ac = new AbortController();
    const s = ac.signal;
    loadPrefs(s).then((p) => setHidden(p.hideStart === true), () => undefined);
    myCredentials(s).then(
      (c) => {
        const k = c.credentials.find((x) => x.kind === 'key' && x.enabled);
        setF((x) => ({ ...x, key: k ? `${c.username}${k.label ? ` · ${k.label}` : ''}` : undefined }));
      },
      () => undefined,
    );
    tenantList(s).then(
      async (ts) => {
        setF((x) => ({ ...x, tenants: ts.length }));
        let n = 0;
        for (const t of ts.slice(0, 20)) {
          n += await networks(t.id, s).then((p) => p.items.length, () => 0);
          if (n) break;
        }
        if (!s.aborted) setF((x) => ({ ...x, networks: n }));
      },
      () => undefined,
    );
    ingress({}, s).then((i) => setF((x) => ({ ...x, hosts: i.tenants.reduce((a, t) => a + t.hosts.length, 0) })), () => undefined);
    return () => ac.abort();
  }, [admin, v.apps.length, v.nodes.length]);
  if (!admin || hidden) return null;
  const steps = startSteps(v, f);
  const done = steps.filter((x) => x.done).length;
  if (done === steps.length) return null;
  const next = steps.findIndex((x) => !x.done);
  const hide = async () => {
    setHidden(true);
    try {
      applyPrefs(await savePrefs({ hideStart: true }));
      toast('시작하기 카드를 숨겼습니다. 내 계정 › 화면 설정에서 다시 켤 수 있습니다.');
    } catch {
      toast('숨긴 상태를 저장하지 못했습니다. 이 화면에서만 숨깁니다.', 'er');
    }
  };
  return (
    <section className="card start-card" aria-label="시작하기">
      <div className="row between">
        <b style={{ fontSize: 16 }}>
          시작하기 · {done}/{steps.length}
        </b>
        <button type="button" className="linkish small muted" onClick={() => void hide()}>
          숨기기
        </button>
      </div>
      <div>
        {steps.map((x, i) => (
          <div key={x.title} className="start-step">
            <i className={x.done ? 'done' : ''} aria-label={x.done ? '끝남' : '아직'} />
            <span>
              <b>{x.title}</b>
              <span className="muted small" style={{ display: 'block' }}>
                {x.sub}
              </span>
            </span>
            {!x.done && (
              <Link className={`btn${i === next ? ' primary' : ''}`} to={x.to}>
                {x.action}
              </Link>
            )}
          </div>
        ))}
      </div>
      <span className="small muted">시스템 관리자에게만 보이고, 끝나거나 숨기면 대시보드에서 사라집니다(내 계정 › 화면 설정에서 다시 켬). 사용자 초대는 작업 공간을 만든 뒤 권합니다.</span>
    </section>
  );
}
