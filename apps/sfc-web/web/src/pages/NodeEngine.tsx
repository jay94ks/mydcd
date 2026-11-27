// SPDX-License-Identifier: Apache-2.0

// 서버 상세 › 엔진 탭 (UI-1E, 캔버스 v240·v241 NodeEngine). 초안.
// 엔진(Seafield Engine, sfed)의 상태·설정·메모리 압박·로그 대기열은 Seafield 웹 계약(#687)이 오면 채운다.
// 지금은 서버 요약의 build 필드(#693)만 실제 값이다.
import { Link } from 'react-router-dom';
import type { NodeView } from '../api/types';
import { Badge, Card, HelpBox, KV, type Tone } from '../components/ui';

/** 엔진 정보 › 빌드 칸 (캔버스 NodeEngineIx 표) */
export function engineBuild(node: NodeView): { tone: Tone; text: string; why?: string } {
  const b = node.build;
  if (!b) return { tone: 'un', text: '알 수 없음', why: '서버가 아직 빌드 여부를 보고하지 않았습니다' };
  if (b.enabled) return { tone: 'ok', text: '받을 수 있음' };
  if (b.reason === 'ENGINE_BUILD_OFF') return { tone: 'wa', text: '꺼짐 · 엔진 설정', why: '엔진 설정(node.yaml)에서 이미지 빌드를 껐습니다' };
  if (b.reason === 'WORKLOAD_OFF') return { tone: 'wa', text: '꺼짐 · 서버 역할', why: '서버 설정에서 이 서버에 작업을 놓지 않게 했습니다' };
  return { tone: 'un', text: '알 수 없음', why: '엔진에서 답을 받지 못했습니다' };
}

const PENDING = <span className="muted">아직 보고 없음</span>;

export function EngineTab({ node }: { node: NodeView }) {
  const build = engineBuild(node);
  return (
    <div className="col" style={{ gap: 16 }}>
      <HelpBox terms="엔진 (Seafield Engine, sfed) · 이벤트 열 (번호 붙은 엔진 이벤트) · 로그 대기열 (log queue) · 압박 (PSI, pressure) · OOM (메모리 부족 종료)">
        <b>이 화면은</b> 이 서버에서 컨테이너를 돌리는 Seafield 엔진의 상태와 설정입니다. 엔진은 서버마다 하나이고 sfcd만 엔진에 접속합니다. 여기서 바꾼 설정은 서버 설정(node.yaml)에 남고 엔진에 반영됩니다.
      </HelpBox>
      <div className="bn info small">이 서버는 아직 엔진 상태(버전·이벤트 열·로그 대기열·메모리 압박)를 보고하지 않습니다. 지금은 이미지 빌드 여부만 보입니다.</div>
      <Card title="엔진 정보">
        <KV
          items={[
            ['이름 · 버전', PENDING],
            ['API 버전', PENDING],
            ['시작 표지 (boot)', PENDING],
            ['이벤트 열', PENDING],
            [
              '빌드',
              <span key="b">
                <Badge tone={build.tone}>{build.text}</Badge>
                {build.why && <span className="small muted"> {build.why}</span>}
                {node.build && !node.build.enabled && node.build.reason === 'WORKLOAD_OFF' && (
                  <>
                    {' '}
                    · <Link to={`/servers/${encodeURIComponent(node.id)}`}>서버 상세 › 개요</Link>
                  </>
                )}
              </span>,
            ],
          ]}
        />
      </Card>
      <Card title="엔진 설정" actions={<span className="small muted">서버 설정(node.yaml) · 시스템 관리자</span>}>
        <KV
          items={[
            ['이미지 빌드', node.build ? (node.build.enabled ? '켜짐' : node.build.reason === 'ENGINE_BUILD_OFF' ? '꺼짐' : '—') : PENDING],
            ['로그 알림 대기', PENDING],
            ['로그 알림 최대 대기', PENDING],
            ['컨테이너별 대기열 상한', PENDING],
          ]}
        />
      </Card>
      <Card title="메모리 · 압박 (컨테이너별)">
        <span className="small muted">컨테이너마다 메모리 부족 종료(OOM) 횟수와 CPU·메모리·IO 압박(PSI some avg10)을 보입니다. 엔진이 보고하면 채워집니다.</span>
      </Card>
      <Card title="로그 대기열 (컨테이너별)">
        <span className="small muted">엔진은 로그를 보관하지 않고, sfcd가 가져가 보관할 때까지만 둡니다. 상한을 넘으면 가장 오래된 줄부터 버리고, 버린 구간은 로그 화면에 ‘빠진 줄’로 보입니다. 엔진이 보고하면 채워집니다.</span>
      </Card>
    </div>
  );
}
