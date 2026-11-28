// SPDX-License-Identifier: Apache-2.0

// 더보기 탭 (캔버스 UI-M0 ②). 데스크톱 왼쪽 메뉴와 같은 순서이고, 홈과 장애 대응은 탭이라 뺀다.
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom';
import { opsList } from '../api/endpoints';
import { useAuth, useSession } from '../auth/session';
import { until } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { usePhone } from '../lib/viewport';
import { NAV } from '../layout/AppShell';
import { useMobileTop } from './top';
import { opsLive } from '../lib/liveTopics';

export function MorePage() {
  const phone = usePhone();
  const session = useSession();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const admin = session.user.systemAdmin;
  const ops = usePoll((s) => (phone ? opsList('unknown', s).catch(() => []) : Promise.resolve([])), [phone], 0, opsLive);
  const unknown = ops.data?.length ?? 0;
  useMobileTop({ title: '더보기', root: true }, []);
  if (!phone) return <Navigate to="/" replace />;
  return (
    <div className="m-col" style={{ gap: 10 }}>
      <div className="li">
        <Link to="/account">
          <span className="ic">{session.user.username.slice(0, 1)}</span>
          <span>
            {session.user.username}
            <span className="sub2">
              {admin ? '시스템 관리자' : '사용자'} · 세션 만료 {until(session.expiresAt)}
            </span>
          </span>
          <span className="r">계정 ›</span>
        </Link>
      </div>
      <div className="li">
        {admin && (
          <Link to="/servers">
            <span className="ic">▦</span>서버<span className="r">›</span>
          </Link>
        )}
        <Link to="/deploy">
          <span className="ic">⇪</span>배포된 앱<span className="r">›</span>
        </Link>
        <Link to="/system/ops">
          <span className="ic">≡</span>작업 기록<span className="r">{unknown > 0 ? `${unknown} 불명 ›` : '›'}</span>
        </Link>
      </div>
      <div className="m-sec">
        <span>보기만 · 고치기는 넓은 화면에서</span>
      </div>
      <div className="li">
        <Link to="/standalone">
          <span className="ic">▢</span>단독 컨테이너
          <span className="r">
            <span className="ro">보기만</span>›
          </span>
        </Link>
        <Link to="/images">
          <span className="ic">◫</span>이미지 관리
          <span className="r">
            <span className="ro">보기만</span>›
          </span>
        </Link>
        <Link to="/more/shared">
          <span className="ic">⇄</span>공유 자원<span className="r">망 · 외부 접속 · 저장소 · 비밀값 · 상태 검사 ›</span>
        </Link>
        <Link to="/more/system">
          <span className="ic">⚙</span>시스템<span className="r">{admin ? '작업 공간 · 사용자 · AI · 웹 앱 ›' : '작업 공간 ›'}</span>
        </Link>
      </div>
      <div className="li">
        <button type="button" className="red" onClick={() => void logout().then(() => navigate('/login'))}>
          <span className="ic">⎋</span>로그아웃
        </button>
      </div>
    </div>
  );
}

/** 공유 자원 · 시스템: 한 단계 더 들어가는 목록 */
export function MoreGroupPage() {
  const { group } = useParams();
  const phone = usePhone();
  const session = useSession();
  const sect = group === 'shared' ? '공유 자원' : '시스템';
  useMobileTop({ title: sect }, [sect]);
  const g = NAV.find((x) => x.sect === sect);
  if (!phone || !g) return <Navigate to="/" replace />;
  const items = g.items.filter((it) => !it.admin || session.user.systemAdmin);
  // 시스템 묶음에서 작업 기록은 더보기 첫 화면에 따로 있다
  return (
    <div className="m-col" style={{ gap: 10 }}>
      <div className="li">
        {items
          .filter((it) => it.to !== '/system/ops')
          .map((it) => (
            <Link key={it.to} to={it.to}>
              {it.label}
              <span className="r">
                <span className="ro">보기만</span>›
              </span>
            </Link>
          ))}
      </div>
    </div>
  );
}
