// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import type { MockFailure } from '../api/mock/router';

type Controls = typeof import('../api/mock/router').mockControls;

/** 목업 계층일 때만: 실패 주입(결과 불명·거부·버전 충돌·합의 없음·연결 끊김)과 세션 만료 */
export function MockBar() {
  const [ctl, setCtl] = useState<Controls>();
  const [next, setNext] = useState<MockFailure>('none');
  useEffect(() => {
    void import('../api/mock/router').then((m) => setCtl(m.mockControls));
  }, []);
  if (!ctl) return null;
  return (
    <div className="banner-mock" role="note">
      <b>목업 계층</b>
      <span>실제 sfcd가 아닌 화면 개발용 가짜 응답입니다.</span>
      <label className="row" style={{ gap: 4 }}>
        다음 변경 요청:
        <select
          value={next}
          onChange={(e) => {
            const v = e.target.value as MockFailure;
            ctl.nextMutation = v;
            setNext(v);
          }}
        >
          <option value="none">정상 처리</option>
          <option value="unknown">결과 불명(응답 유실)</option>
          <option value="denied">권한 거부</option>
          <option value="condition-failed">버전 충돌</option>
          <option value="unavailable">합의 없음</option>
          <option value="disconnected">sfcd 연결 끊김</option>
        </select>
      </label>
      <button type="button" className="btn sm" onClick={() => ctl.expireSession()}>
        세션 만료시키기
      </button>
    </div>
  );
}
