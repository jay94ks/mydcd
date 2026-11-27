// SPDX-License-Identifier: Apache-2.0

// 전체 찾기 오버레이(Ctrl/⌘+K, 캔버스 v224 StartSearch UI-10A). 열 때 내 권한으로 읽을 수 있는 목록을 모아 이름으로 찾는다.
// 찾기 전용 끝점은 없어 기존 목록 API를 묶는다. 하나가 실패해도 나머지로 찾는다.
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { appPath, apps, images, networks, nodesOverview, users, volumes } from '../api/endpoints';
import { ingress } from '../api/ingress';
import { useAuth, useSession } from '../auth/session';
import { NAV } from '../layout/AppShell';
import { searchHits, type Hit } from '../lib/search';
import { HEALTH } from './ui';

/** 메뉴에 없는 화면(탭)도 이름으로 찾는다 */
const EXTRA_SCREENS: [string, string, boolean?][] = [
  ['망 · 연결 › 도메인 이름', '/shared/networks/dns'],
  ['망 · 연결 › 작업 공간 간 연결', '/shared/networks/routes'],
  ['서버 › 합의 상태', '/servers/consensus', true],
  ['서버 › 클러스터 앱', '/servers/cluster-apps', true],
  ['서버 › VPS 관리', '/servers/vps', true],
  ['배포 › 새 앱 배포', '/deploy/new'],
  ['배포 › 내린 앱', '/deploy/archived'],
  ['이미지 관리 › 이미지 올리기', '/images/upload'],
  ['이미지 관리 › 저장소', '/images/registry'],
  ['이미지 관리 › 이미지 신뢰', '/images/trust'],
  ['이미지 관리 › 외부 저장소', '/images/external'],
  ['이미지 관리 › 이미지 빌드', '/images/builds'],
  ['장애 대응 › 대응 정책', '/incidents/policy'],
  ['장애 대응 › 대응 지침', '/incidents/guide'],
  ['장애 대응 › 웹훅', '/incidents/hooks'],
  ['외부 도메인 › 인증서', '/system/domains/certs', true],
  ['작업 기록 › 관리 변경', '/system/ops/changes'],
  ['작업 기록 › 자원', '/system/ops/resources'],
  ['작업 기록 › 웹', '/system/ops/web'],
  ['작업 기록 › 지운 것', '/system/ops/trash'],
  ['AI 설정 › MCP', '/system/ai/mcp', true],
  ['알림', '/notifications'],
  ['내 계정', '/account'],
  ['내 계정 › 알림 설정', '/account/notify'],
  ['코디네이터', '/coordinator'],
];

function useHits(open: boolean) {
  const session = useSession();
  const admin = session.user.systemAdmin;
  const [hits, setHits] = useState<Hit[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!open) return;
    const ac = new AbortController();
    const s = ac.signal;
    const tenants = session.tenants.map((t) => t.id);
    const base: Hit[] = [
      ...NAV.flatMap((g) => g.items.filter((it) => (!it.admin || admin) && !it.shellOnly).map((it): Hit => ({ kind: '화면', label: it.label, to: it.to, keys: it.to }))),
      ...EXTRA_SCREENS.filter(([, , a]) => !a || admin).map(([label, to]): Hit => ({ kind: '화면', label, to, keys: to })),
      ...tenants.flatMap((t): Hit[] => [
        { kind: '작업 공간', label: t, sub: session.tenants.find((x) => x.id === t)?.role === 'viewer' ? '읽기' : undefined, to: `/system/tenants/${encodeURIComponent(t)}` },
        { kind: '화면', label: `작업 공간 › ${t} › 권한`, to: `/system/tenants/${encodeURIComponent(t)}` },
        { kind: '화면', label: `작업 공간 › ${t} › 허용 서버`, to: `/system/tenants/${encodeURIComponent(t)}/nodes` },
        ...(session.tenants.find((x) => x.id === t)?.role !== 'viewer' ? [{ kind: '동작' as const, label: `${t}에 앱 배포…`, sub: '배포 마법사', to: '/deploy/new', tenant: t }] : []),
      ]),
    ];
    setHits(base);
    const add = (more: Hit[]) => !s.aborted && setHits((h) => [...h, ...more]);
    // 이 실행의 남은 요청 수(취소된 실행은 화면 상태를 건드리지 않는다)
    let pending = 0;
    const job = (p: Promise<Hit[]>) => {
      pending++;
      setLoading(true);
      void p
        .then(add, () => undefined)
        .finally(() => {
          pending--;
          if (!s.aborted) setLoading(pending > 0);
        });
    };
    for (const t of tenants.slice(0, 20)) {
      job(apps(t, s).then((p) => p.items.map((a): Hit => ({ kind: '앱', label: a.app, sub: `${t} · ${(HEALTH[a.health] ?? HEALTH.unknown)[1]}`, to: appPath(t, a.app), tenant: t }))));
      job(networks(t, s).then((p) => p.items.map((n): Hit => ({ kind: '망', label: n.name, sub: `${t} · 서버 ${n.nodes.length}`, to: `/shared/networks?net=${encodeURIComponent(n.name)}`, tenant: t }))));
      job(volumes(t, s).then((p) => p.items.map((v): Hit => ({ kind: '데이터 저장소', label: v.name, sub: t, to: '/shared/volumes', tenant: t }))));
      job(images(t, s).then((p) => p.items.map((i): Hit => ({ kind: '이미지', label: `${i.repo}:${i.tag}`, sub: t, to: '/images', tenant: t, keys: i.registry }))));
    }
    job(
      ingress({}, s).then((v) =>
        v.tenants.flatMap((x) => x.hosts.map((h): Hit => ({ kind: '외부 접속', label: h, sub: x.tenant, to: admin ? '/shared/ingress?view=route' : '/shared/ingress', tenant: admin ? undefined : x.tenant }))),
      ),
    );
    if (admin) {
      job(nodesOverview(s).then((o) => o.nodes.map((n): Hit => ({ kind: '서버', label: n.id, sub: n.endpoint, to: `/servers/${encodeURIComponent(n.id)}` }))));
      job(users(s).then((p) => p.items.map((u): Hit => ({ kind: '사용자', label: u.username, sub: u.enabled ? undefined : '꺼짐', to: '/system/users', keys: u.id }))));
    }
    return () => ac.abort();
  }, [open, admin, session.tenants]);
  return { hits, loading };
}

export function GlobalSearch({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const { hits, loading } = useHits(true);
  const shown = useMemo(() => searchHits(hits, q), [hits, q]);
  const navigate = useNavigate();
  const { setTenant } = useAuth();
  const list = useRef<HTMLDivElement>(null);
  useEffect(() => setSel(0), [q]);
  useEffect(() => {
    list.current?.querySelector<HTMLElement>('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [sel]);
  const go = (h?: Hit) => {
    if (!h) return;
    if (h.tenant) setTenant(h.tenant);
    navigate(h.to);
    onClose();
  };
  return (
    <div className="gs-back" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="gs" role="dialog" aria-modal="true" aria-label="전체 찾기">
        <div className="gs-in">
          <span className="muted" aria-hidden>
            ⌕
          </span>
          <input
            autoFocus
            value={q}
            placeholder="앱·서버·망·외부 접속·데이터 저장소·이미지·작업 공간·사용자·작업 ID·화면"
            aria-label="찾을 이름"
            role="combobox"
            aria-expanded={shown.length > 0}
            aria-controls="gs-list"
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') onClose();
              else if (e.key === 'ArrowDown') (e.preventDefault(), setSel((i) => Math.min(i + 1, shown.length - 1)));
              else if (e.key === 'ArrowUp') (e.preventDefault(), setSel((i) => Math.max(i - 1, 0)));
              else if (e.key === 'Enter' && !e.nativeEvent.isComposing) go(shown[sel]);
            }}
          />
          <span className="muted small">Esc</span>
        </div>
        <div className="gs-list" id="gs-list" role="listbox" ref={list}>
          {shown.map((h, i) => (
            <div key={`${h.kind}/${h.label}/${h.to}/${h.sub ?? ''}`} role="option" aria-selected={i === sel} className={`gs-row${i === sel ? ' on' : ''}`} onMouseEnter={() => setSel(i)} onMouseDown={(e) => (e.preventDefault(), go(h))}>
              <span className="muted">{h.kind}</span>
              <span className="gs-label">{h.label}</span>
              <span className="muted small">{h.sub}</span>
            </div>
          ))}
          {q.trim() && !shown.length && <div className="gs-empty muted small">{loading ? '목록을 읽는 중…' : '찾는 이름이 없습니다.'}</div>}
        </div>
        <div className="gs-foot muted">↑↓ 고르기 · Enter 열기 · 내 권한으로 볼 수 있는 것만{loading ? ' · 목록을 읽는 중…' : ''}</div>
      </div>
    </div>
  );
}

/** Ctrl/⌘+K로 열고 닫는다 */
export function useSearchHotkey(setOpen: (f: (o: boolean) => boolean) => void) {
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [setOpen]);
}
