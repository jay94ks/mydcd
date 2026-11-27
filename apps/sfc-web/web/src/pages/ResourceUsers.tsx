// SPDX-License-Identifier: Apache-2.0

// 망·데이터 저장소 줄 메뉴의 '쓰는 앱 보기'. 데몬이 sfcd의 network-users / volume-users를 그대로 준다.
import { networkUsers, volumeUsers } from '../api/endpoints';
import type { DResourceUser } from '../api/dto';
import { Badge } from '../components/ui';
import { Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { usePoll } from '../lib/usePoll';
import { eulReul } from '../lib/josa';

const who = (u: DResourceUser) => (u.kind === 'standalone' ? (u.standalone ?? '?') : u.kind === 'volume-operation' ? (u.consumer ?? '작업') : `${u.app ?? '?'} / ${u.service ?? '?'}`);

export function ResourceUsersDialog({ tenant, kind, name, app, onClose }: { tenant: string; kind: 'network' | 'volume'; name: string; app?: string; onClose: () => void }) {
  const q = usePoll((s) => (kind === 'network' ? networkUsers(tenant, name, s) : volumeUsers(tenant, name, app, s)), [tenant, kind, name, app]);
  return (
    <Dialog
      title={`${name}${eulReul(name)} 쓰는 앱`}
      onClose={onClose}
      footer={
        <button className="btn primary" onClick={onClose}>
          닫기
        </button>
      }
    >
      <Load q={q} what="쓰는 곳을 불러오지 못했습니다">
        {(d) =>
          d.users.length === 0 ? (
            <p className="muted">이 {kind === 'network' ? '망' : '데이터 저장소'}을 쓰는 앱이나 단독 컨테이너가 없습니다.</p>
          ) : (
            <>
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>앱 / 서비스</th>
                      <th>서버</th>
                      {kind === 'volume' && <th>쓰기</th>}
                      <th>상태</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.users.map((u, i) => (
                      <tr key={i}>
                        <td>
                          {who(u)}
                          {u.kind === 'standalone' && <span className="muted"> (단독 컨테이너)</span>}
                          {u.kind === 'volume-operation' && <span className="muted"> (백업·옮기기가 읽는 중)</span>}
                          {(u.selection?.length ?? 0) > 1 && <span className="small muted"> · 컨테이너 {u.selection!.length}개</span>}
                        </td>
                        <td>{u.node ?? '—'}</td>
                        {kind === 'volume' && <td>{u.readOnly ? '읽기' : '쓰기'}</td>}
                        <td>{u.attached ? <Badge tone="ok">붙어 있음</Badge> : <Badge tone="un">붙지 않음</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )
        }
      </Load>
    </Dialog>
  );
}
