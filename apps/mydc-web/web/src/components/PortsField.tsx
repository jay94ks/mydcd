// SPDX-License-Identifier: Apache-2.0

// 서비스 ports 칸(앱 그래프 속성 칸·app.yaml 폼 UI-38 공통): 같은 힌트와 읽은 결과 미리 보기.
// 값은 app.yaml ports: 그대로다. ports에 적은 포트는 모두 서버 포트로 공개된다(app-and-cluster-spec '서비스의 호스트 포트 직접 공개').
import { parsePort, publishText } from '../lib/ports';
import { Field } from './ui';

export const PORTS_HINT =
  '쉼표로 여러 개. 적은 포트는 서버 포트로 공개합니다: 받을 주소:서버 포트:컨테이너 포트/프로토콜(예: 127.0.0.1:18080:8080/tcp, 15353:53/udp). 컨테이너 포트만 쓰면 서버가 포트를 고릅니다(예: 8080). 망 안에서만 쓸 포트는 적지 않아도 됩니다. 외부 접속 수신 주소는 자동으로 만들지 않음';

export function PortsField({ label = '포트', value, onChange, onBlur, disabled }: { label?: string; value: string; onChange: (v: string) => void; onBlur?: () => void; disabled?: boolean }) {
  const items = value
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  const parsed = items.map((t) => ({ t, p: parsePort(t) }));
  const bad = parsed.filter((x) => !x.p).map((x) => x.t);
  const cols = '1fr 0.7fr 1.6fr';
  return (
    <>
      <Field label={label} hint={PORTS_HINT} error={bad.length ? `읽을 수 없음: ${bad.join(', ')}` : undefined}>
        <input className="mono" value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)} onBlur={onBlur} />
      </Field>
      {parsed.some((x) => x.p) && (
        <div className="gtbl small">
          <div className="gr th" style={{ gridTemplateColumns: cols }}>
            <span>컨테이너 포트</span>
            <span>프로토콜</span>
            <span>서버에 공개</span>
          </div>
          {parsed.map(({ t, p }) =>
            p ? (
              <div key={t} className="gr" style={{ gridTemplateColumns: cols }}>
                <span className="mono">{p.target}</span>
                <span>{p.proto}</span>
                <span className={p.published ? 'mono' : 'muted'}>{publishText(p)}</span>
              </div>
            ) : null,
          )}
        </div>
      )}
    </>
  );
}
