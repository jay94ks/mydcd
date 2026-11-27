# 합의·CAS·원 요청

## 권위와 저장

클러스터의 관리 목표·권한·할당·원 요청 결과는 Raft에 의해 순서가 확정된 결정적 FSM에 적용된다. FSM 적용은 상태·결과·lastApplied를 같은 내구 경계에 남긴다. 노드별 실제 장치·컨테이너·관측 journal은 그 노드가 소유하며 공유 Snapshot으로 덮어쓰지 않는다.

합의 알고리즘과 Raft log는 채택 라이브러리가 담당한다. 별도의 해시체인/Delta를 관리 상태의 두 번째 확정 경계로 두지 않는다. 정족수는 현재 확정된 voter 구성의 `floor(N/2)+1`이다. N2에서는 두 voter가 모두 필요하고, N1 전환은 명시 membership 변경의 확정 결과여야 한다.

## 원 요청의 식별

명령은 원 signer·request ID·epoch·대상·payload·서명과 비교 좌표에 결합된다. 같은 원 요청의 확정/거부 결과를 조회할 수 있어야 하며, 같은 ID로 다른 내용을 실행하지 않는다.

| 상황 | 처리 원칙 |
|---|---|
| 현재 대상 revision 또는 서명된 target이 다름 | CAS 거부 결과를 보존 |
| 같은 원 명령을 다시 조회 | 원 결과를 반환 |
| 전송 전에 확실히 중단 | NotSent로 구분 |
| 전송 뒤 timeout·단절·취소 | Unknown일 수 있으므로 원 작업을 관측/정산 |
| 새로운 의도가 필요 | 기존 결과를 보존하고 명시된 새 변경으로 처리 |

[SFCP 요청 수명 코어](../../internal/sfcp/request.go)는 `Prepared → InFlight → Completed`와 `NotSent/Unknown`을 구분한다. frame의 `Request`는 통신 교환 ID이고, 업무 request/operation ID의 내구 식별과 별개다.

## 비교 좌표

일반 객체 변경은 해당 계약의 revision CAS를 사용한다. CD의 기본 sync/recover는 실행 의도 target CAS를 사용하고, 명시 `--expected-revision`은 엄격 CAS를 사용한다. 신규 앱은 expected=0과 이름별 부재 지문을 함께 검증하고, 기존 plain 앱 갱신은 원 BeginTarget을 검증한다. 다른 앱의 checkpoint를 해당 앱의 생성/변경으로 간주하지 않는다. 앱 down·field 변경·upload 등도 각 action에 정의된 비교 대상을 사용한다. 특정 action의 target CAS를 다른 변경에 자동 적용하지 않는다.

상태 전이 안에서는 외부 시각·난수·네트워크·OS 관측을 새로 생성하지 않는다. 필요한 외부 사실은 검증된 입력으로 전달하고, 외부 효과 수행과 관리 상태 커밋을 구분한다.

구체적 명령별 좌표·권한은 [명령 대상표](../architecture/command-targets.md), wire/서명은 [SFCP](../protocol/sfcp.md), 구현은 [cluster/state](../../internal/cluster/state/)를 따른다.
