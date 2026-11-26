## Tenant 전체 삭제

| 명령/메서드 | 적용 대상·권한 | 수락/완료 경계 |
|---|---|---|
| `tenant delete` (`begin-tenant-retirement` → `finish-tenant-retirement`) | payload Tenant·원 Operation·tenant revision CAS. 현재 system administrator와 일반 catalog root CAS·quorum | 원 inventory는 FSM이 수집. begin은 신규 수락 차단이며 기존 자원 종료/데이터 정산은 명시 작업. finish는 owner 전체의 양성 종료 보고와 현재 잔여0 뒤 tombstone. 멈추면 `op resume`이 같은 요청을 계속 |
| `tenant delete`의 대기·`op show` (User `tenant-retirement`) | 현재 system administrator의 명시 원격 tenant | 상태/원 target·owner·closed 수와 잔여 최대8개. 원본 inventory와 owner 서명은 FSM 보존. 같은 Index/root의 페이지만 합침. Deleted도 system scope로 조회 |
| MYDCP `tenant-retirement-work` / `tenant-retirement-report` | 기존 인증 member lane, 원 inventory의 정확한 owner key와 동일 operation/시작 revision/digest·epoch/root | work는 원 owner의 정산 좌표. 공유 잔여0/실제 native·I/O 종료 뒤 폐기 가능한 engine-owned build cache만 원 RootManager lease 아래 회수. Volume/backup은 기존 명시 삭제 유지. report는 실제 종료 서명과 원 receipt를 확정하며 새 업무 권한을 주지 않음. [캐시 회수](../../reference/image-build-jobs/17-tenant.md) |

상세 계약은 tenant 삭제 런타임을 따른다.

`registry start/stop`의 기다림은 원 tenant registry를 조회하며 unavailable/not-leader의 일시적 quorum 실패만 기존 wait 기한 안에서 재관측한다. 다른 인증/권한·전송·입력 오류를 숨기거나 로그인/생성/재제출로 대체하지 않는다.

`app diff`의 서버측 선언 거부는 `invalid`와 안전한 planner 심볼 코드(`InputCode`)를 함께 표시할 수 있다. `VOLUME_NOT_MOVABLE` 같은 배치 거부와 다른 입력 오류를 구분하며 원문/개인 경로/Secret은 표시하지 않는다. 이 진단은 원 작업 수락·권한이나 자동 재제출을 의미하지 않는다.

관리 원 결과 조회의 현재 전송/quorum 오류는 `status: unknown`·exit4·원 intent를 유지하며 안전한 `error_code`로 구분한다. 오류 원문/자격/명령 payload를 노출하지 않고 과거 저장 Result를 현재 승인으로 대체하지 않는다. 원 result 재조회와 apply/resume 재제출은 별개다.


기본 `cd configure`는 공개 실행 의도 Target과 원 정책 revision을 고정하는 `app-configure-target` CAS를 사용한다. 같은 앱의 health/fetch 관측·다른 앱의 root 전진은 무시하지만 실제 정책·등록·후보/실행·pause/down/override 변경은 거부한다. 명시 `--expected-revision`과 Target 없는 legacy 요청은 전체 CD revision/root CAS를 유지한다. 기존 거부/Unknown 요청은 새 모드로 전환하지 않으며 원 서명·요청·결과를 보존한다.


`manage result/resume`의 선택 tenant 일치 검사는 원 app Target 지문(array32)과 자원 Target scope 객체를 action별로 구분한다. app 원 Tenant 및 자원의 중첩 대상 tenant를 대조하고 잘못된 target 형식은 거부한다. 원 결과 조회는 이 해석 때문에 payload/서명/ID를 재작성하거나 재제출하지 않는다.


`app deploy의 기본 대기`는 현재 수락된 CD update/recover가 그 ID를 선택한 retiring/ready/applying 단계도 같은 유한 기한으로 관측한다. queued 후보를 수락으로 취급하지 않으며 다른 operation/retirement·down은 거부한다. 활성화된 원 operation의 Succeeded와 현재 Healthy만 성공이고, wait가 효과를 제출하거나 재개하지 않는다.

| 관리 변경 | 인증·적용대상 | 보존·실행 규칙 |
|---|---|---|
| `manage apply` action `resume-app-retirement` / 같은 `manage result,resume` | 현재 계정의 tenant Deploy cleanup 권한과 원 종료 권한. payload Tenant/App/Retirement/Key/Phase/Command, Expected=현재 Inventory revision, 현재 root CAS/quorum | 원 RecoveryRequired Raft 명령의 한 번 재전송 허가만 저장. status의 `Retirement.Pending`으로 정확한 원 좌표를 조회. 같은 요청은 같은 허가/결과만 조회하며 소진 후 자동 갱신하지 않음. 원 Command/ID/기한/Unknown·native pin 보존, late result 우선 수집. app/CD/관리 명령 자동 작업 대상 아님 |

예약된 망의 기존 DNS를 종료하는 새 `configure-network-dns` 변경은 `RetainReserved: true`로 원 구성원 검증을 명시할 수 있다. disabled·기존 source에만 허용하며 필드 없음/false는 기존 검증·과거 거부 의미를 유지한다. source CAS·현재 cleanup 권한·원 owner/lifetime closure는 동일하다.

