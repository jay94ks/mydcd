# CD 후보 승인·반려

후보 승인은 배포할 입력을 승인하는 동작이다. 기존 `cd approve`의 Secret Group 비밀번호 승인과 구분한다.

```sh
mydc --tenant team-a cd status shop
mydc --tenant team-a --reason '릴리스 검사 통과' --incident-id release-42 \
  cd approve-candidate shop --candidate SHA256 --request-id approve-42
mydc --tenant team-a --reason '외부 검사 실패' \
  cd reject-candidate shop --candidate SHA256 --request-id reject-42
mydc --tenant team-a cd replan shop --request-id reconsider-42
```

현재 tenant의 `ManageCD`가 필요하다. credential에 동작 제한이 있으면 각각 `cd-approve`, `cd-reject`를 허용해야 한다. 이유는 선택 전역 `--reason`으로 받고 최대512자이며 원 operation에 서명한다. `--incident-id`/`--approved-by`도 기존 metadata 규칙을 따른다. 승인 표시 문자열은 권한을 만들지 않는다. 이유는 공개 작업 metadata이므로 Secret·환경 변수 값·비밀번호를 입력하지 않는다.

## 원 대상과 CAS

두 명령은 기존 User 서명 operation을 사용한다.

| 필드 | 값 |
|---|---|
| Change.Action | cd-approve 또는 cd-reject |
| Change.Expected | 읽은 CD revision |
| Change.Payload | `{Tenant,App,Candidate,Target,Strict?}` |
| Candidate | 현재 CD 후보 SHA-256, wire는 기존32 byte 배열 |
| Target | 현재 앱 CD 실행 의도 지문 |
| Strict | 생략/false면 후보·실행 의도 CAS, true면 CD/root revision도 정확히 일치 |
| RootRevision | Apps root |
| Reason | 기존 `{Text,IncidentID?,ApprovedBy?}` metadata |

CLI의 `--candidate`는 `cd status`에서 읽은 정확한 후보를 명시한다. `--expected-revision N`을 추가하면 strict CAS를 선택한다. 기본 모드도 후보·원 등록·실행 의도·현재 권한이 바뀌면 거부한다. 상태 보고만 바뀐 incidental inventory는 같은 source/commit/실행 의도인지 확인한 뒤 재기준화한다. 원 사용자의 후보 선택·서명은 보존한다.

재실행은 새 후보를 읽기 전에 원 journal을 찾는다. 같은 request ID에 다른 앱·동작·후보·CAS를 덮어쓰지 않는다. `--resume-original`은 저장된 원 operation만 명시 재제출하며 후보를 생략할 수 있다. 새 후보를 자동 선택하거나 새 요청 ID를 발급하지 않는다. 실제 결과는 기존 `manage result`와 `cd status`로 조회한다.

## 승인 이후 실행

승인은 Secret Group 승인이나 Deploy 권한을 만들지 않는다. 수동 CD 모드에서도 명시 후보 승인이 있으면 기존 CD worker가 같은 원 앱 Inventory로 실행을 진행한다. 실행 전 현재 승인 계정/credential/동작 제한·원 배포 principal의 현재 권한·배치·원 Secret Group 승인·Volume 등을 확인한다. Group 암호/승인이나 배치가 부족하면 기다리며 `cd approve-candidate`로 그 단계를 대신하지 않는다.

승인은 정확한 source/commit/실행 의도에 고정한다. 같은 의도의 CAS/readiness 재기준화에만 유지하며 새로운 source·정책·override 후보에는 전달하지 않는다. 계정/catalog 변경으로 승인이 현재 조건을 충족하지 않으면 재승인이 필요하다. 이미 수락한 배포의 원 Task·grant·불명 정산은 기존 실행 계약을 따른다.

현재 권한 모델은 tenant `ManageCD`와 credential 동작 제한을 사용한다. 이 문서는 app별 `ApproveCD:<app>` 권한을 제공한다고 주장하지 않는다. 후보 승인 계정에 `cd-approve`/`cd-reject`만 허용하면 다른 typed 관리 변경은 할 수 없으며, 같은 tenant의 다른 앱 승인까지 제한하려면 별도 app 범위 계약이 필요하다.

## 반려와 재계획

반려한 Git commit은 다시 fetch되거나 source/cache가 복구되어도 자동으로 승인/실행하지 않는다. 자동·수동 sync와 후보 승인 모두 해당 source가 반려 중이면 거부한다. 새 commit은 별도 후보이며, 과거 반려 commit으로 돌아오면 원 반려가 다시 적용된다. file source는 원문 digest로 구분한다. 반려 이력은 앱당128개까지 보존하고 한도가 차면 과거 반려를 버려 자동 실행하는 대신 새 반려 요청을 거부한다.

명시적인 `cd replan`만 현재 source의 반려를 해제할 수 있다. 기본 replan은 `{Tenant,App,Target}`을 서명하고, 후보·원 등록·정책·override·실행/종료 의도를 고정한다. 주기적인 source/health 관측만 바뀌면 현재 상태에서 같은 후보를 재계획할 수 있다. `--expected-revision N`은 Target을 생략하는 기존 CD/root strict CAS를 유지한다. 원 journal을 불러온 요청의 CAS 모드는 바꾸지 않는다. 일반 fetch·자동 replan·incidental rebase는 해제하지 않는다. 수동 모드에서 재계획한 후보는 다시 승인을 받아야 한다. 이미 실행 중인 미완료 후보를 뒤늦게 반려하여 수락 기록을 취소하지 않는다. 정지가 필요하면 기존 pause/down과 원 작업 정산을 사용한다.

## 공개 조회

기존 app/CD 조회의 `CD.Decision`은 `{Action,User,At,Reason?,Selection}`이다. Selection은 원 Candidate/Artifact/Plan/Intent/Commit을 포함한다. 사용자 Session·서명·자격 backend는 반환하지 않는다.

`CD.Status`는 현재 반려 시 `Rejected=true`, `Operation="Rejected"`, `Rejection={Source,Candidate,Actor,Reason,CatalogRevision}`을 포함한다. 아직 소비하지 않은 승인에는 `ApprovalActor`/`ApprovalReason`을 표시한다. 실행이 승인을 소비한 뒤에도 `CD.Decision`에서 원 사용자/이유를 읽는다. 현재 정책·source·실행/health와 승인 metadata는 서로 다른 정보다.

CD cursor 이벤트의 연결은 RQ4의 내구 이벤트 구현에서 같은 원 결정/후보/실행을 사용한다. 웹훅 호출과 UI는 별도 소비자 작업이다.

## 일시정지·재개와 이전 버전

`mydc --tenant team-a cd pause shop --preview`와 `cd resume shop --preview`는 사용자 조회 `app-cd-toggle-plan`을 호출한다. 요청은 `{Tenant,CDToggle:{App,Action}}`이며 Action은 `pause-app-cd`/`resume-app-cd`다. `CDTogglePlan`은 Schema=1, Tenant/App/Action, 현재 Expected CD revision·RootRevision·Epoch, Paused/WouldPause, ActiveOperation, PreservesOriginal=true를 반환한다. 실제 reducer와 같은 순수 전이를 평가하며 현재 권한·동작 제한·Volume 이동/진행 충돌도 동일하게 검사한다. 미리보기는 상태를 바꾸거나 이후 성공을 예약하지 않는다.

실행은 `cd pause shop --request-id ID` / `cd resume shop --request-id ID`로 원 UserOperation을 저장하고 제출한다. 사유 옵션을 사용할 수 있으며 재호출은 원 journal/result를 사용한다. `--preview`와 request ID·expected-revision·resume-original을 혼합하지 않는다. pause는 이미 수락된 작업을 미실행으로 바꾸지 않고 원 ActiveOperation·Task·grant를 유지한다. resume도 같은 원 실행을 보존하며 명시 down의 정산이 남으면 거부한다.

이전 버전은 `manage app-revisions --app shop`에서 선택하고 `manage app-source --app shop --revision N --section source --raw`로 원문을 읽는다. 공개 버전에는 원 Commit·Digest·Operation·수락/완료 시각과 원문 보존 여부가 있다. overlay도 같은 revision의 `--section overlays`로 읽는다. 보존되지 않은 원문을 현재 입력으로 대신하지 않는다. 선택한 원문을 파일로 보관하고 기존 app diff로 현재 배치·권한·Secret/Volume 참조를 검토한 후 새 명시 배포 작업으로 실행한다. 과거 버전 선택은 현재 자격·권한·Secret 승인을 복구하지 않으며, 원 작업 ID를 새 배포에 재사용하지 않는다.
