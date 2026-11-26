## 유지 규칙

앱/이관 단계가 거부되면 CLI는 로컬 원 operation에서 읽은 request/action·epoch·root_revision과 expected_revision을 결과와 함께 출력한다. 기본/과거 요청의 root_revision은 서명된 모듈 root CAS다. artifact upload의 begin/part/abort는 서버가 Change의 action으로 upload CAS를 정하며 CLI는 cas=upload를 출력한다. 이 모드에서 root_revision은 원 관측 지점이고 expected_revision은 정확한 upload의 생성0/현재 revision CAS다. 현재 권한/예산·digest·원 결과는 유지하고 앱 수락/이관/기타 관리 변경은 기존 CAS를 적용한다. 거부 결과의 Revision만으로 두 CAS를 같은 값으로 해석하지 않는다. 진단 출력이나 재로그인이 과거 원 요청을 새 모드로 전환/재서명/재제출하지 않는다.

명령/별칭·전역/하위 옵션·인증 주체·적용대상·입력/원 결과·자원 수명이 바뀌면 같은 작업에서 이 표, 자원표, 해당 명세/도움말/예시를 갱신한다. 구현 전 문법은 후속 계약으로 표시한다. 실제 handler/API와 소비 계약이 연결될 때 해당 경계를 검증하며 문서 이동 때문에 실행 시험을 반복하지 않는다. 완료 수치·실행 이력은 이 표에 누적하지 않는다.


### 내부 앱 진행·CD source 호출

| 내부 요청 | 적용 대상/권한 | 결과와 경계 |
|---|---|---|
| MYDCP `app-progress` | 현재 member의 원 tenant/app·operation·Step/journal에 대한 내부 진행 보고 | observe가 아닌 진행 보고는 정확한 app inventory Expected와 양수/현재 이하 Apps basis를 사용. 원 member/권한/epoch·원 명령 및 atomic 관련 자원 검증 유지. observe는 관측 target을 사용. legacy는 strict root/원 bytes 유지. 사용자 관리 CAS·native Unknown 재제출 권한으로 확대하지 않음 |
| MYDCP `app-delivery-permit` | current member의 latest quorum 조회. 원 tenant/app 등록·현재 CD 권한·source policy/ticket | reader·module epoch·Apps root/Delivery CAS·원 upload progress. Git 자격/실제 source part나 native 실행 권한을 반환하지 않음 |
| MYDCP `app-delivery-sync-work` | current member의 latest quorum 조회. 현재 source/권한·정확한 candidate·원 실행과 실제 health | 같은 reducer의 replan/auto-sync/continue 전이를 미리 계산. Apps root/CD revision/module epoch·정확한 선택만 반환하며 native 실행 권한이 아님. manual/paused·불명/실패·미종료/권한 부족은 새 자동 작업을 만들지 않음 |
| MYDCP `app-delivery-progress` | signed current member ModuleReport. fetch/input/part/received는 원 ticket/현재 등록 권한, source-error는 원 ticket의 읽기 정산. replan/auto-sync/continue는 같은 현재 work preview와 CAS 대조 | 기존 Apps/Upload의 후보 게시 또는 같은 Delivery/Inventory의 선택·양성 종료 후 계속만 수행. native 효과는 기존 앱 실행기/원 retirement 경로가 담당하고 관리 자원을 CD로 변경하지 않음. source 오류로 현재 앱을 삭제하지 않음 |

이 요청들은 daemon 내부 source/선택·실행 진행 어댑터 경계다. source 등록은 app.yaml의 명시 CD 정책을 포함한 기존 app deploy이며 planning의 `git-cd`로 선언/연결 입력 지원을 게시한다. 실제 fetch·적용/health·전체 검증과는 구분하며 완료 여부는 Milestones/HISTORY를 따른다. 명령 문법이나 source 후보를 native 성공으로 해석하지 않는다.

사용자 MYDCP 조회 `app-cd-field`는 tenant/app/정확한 field, `app-cd-registration`은 tenant/app/명시 candidate 또는 operation selector에 결합한다. 후자는 원 등록자와 같은 현재 사용자에게 공개 signed 등록과 실제 approval realm만 반환한다. 기존 vault-approval-plan/permit·보호 SecretInput·signed VaultApprovalReport의 optional Selection이 같은 원 선택을 전달하며, 임의 caller의 recipe나 unsigned 원 requester를 받지 않는다. 새 합의/RPC/승인 실행기는 만들지 않는다.


### CD 앱의 Volume 이관과 이력 회수

기존 `volume move`(계획은 `--dry-run --save-plan`)와 `op resume`, 서버의 commit/취소를 사용한다. CD 앱의 이동 계획에서 Deployment를 생략하면 원 Inventory scope를 사용하고 명시한 다른 값은 거부한다. CD 앱의 target artifact는 등록 principal·원 requester와 현재 source 정책에 고정하며 signed move의 CD anchor와 같이 검증한다. 다른 현재 관리자의 명시 이관이 원 등록을 덮지 않으며 현재 이관/원 등록 grant를 모두 요구한다. local private move intent는 실제 관리자의 namespace에 있고 Source actor와 구분한다. cd approve --operation MOVE_ID는 원 등록자의 Group 승인 경로다. 이관 중 새 CD 선택/정책/field 변경으로 원 target을 바꾸지 않는다. owner가 바뀌는 field override는 먼저 explicit release한다.

rotate-app-history는 기존 Inventory revision·Apps root CAS와 이미 커밋된 A1 epoch floor를 사용한다. CD는 현재 sync 선택의 결과와 원 등록 서명을 따로 보존하고 같은 Delivery.RotateWindow로 원 transition ID/floor·마지막 성공/실패를 정산한다. 모든 원 claim의 종료·Binding 반환·quiescent/down 조건이 필요하며 retained/Unknown을 expiry만으로 회수하지 않는다. CD 회수에는 현재 Deploy 및 ManageCD cleanup 권한이 필요하다. 비CD의 원 등록 결과/회수 계약은 유지한다.

