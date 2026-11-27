# app.yaml 원문과 배포 버전

`app-source`와 `app-revisions`는 특정 tenant 앱에서 수락된 원문과 보존 버전을 읽는다. 조회가 배포·되돌리기·Secret 공급을 실행하지 않는다.

## 버전의 의미

원문은 공백·주석까지 입력 바이트 그대로다. 정규화된 실행 설정을 YAML로 다시 만들어 원문으로 반환하지 않는다. 새 계획은 기존 컴파일러의 정규화 결과와 원문이 일치하는지 검사하며, Blueprint와 같은 수락 FSM 변경으로 원문을 보존한다. 버전 번호는 앱별로1에서 시작해 새 배포 실행을 수락할 때 증가한다. 관측·상태 보고·CD fetch·미실행 후보·컨테이너 로그 정리만으로 번호를 늘리지 않는다.

기본 조회 대상은 현재 실행에 선택된 최신 수락 버전이다. 아직 배포가 끝나지 않았으면 `Status`로 구분한다. CD가 이전 실행을 정리하며 새 실행을 기다리는 동안에는 이전 버전이 기본 대상이다. 새 실행을 시작하면 그 버전이 기본 대상이 된다.

이 기능 이전에 수락한 Blueprint에는 원문이 없을 수 있다. 이런 버전은 `OriginalRetained:false`이고, 원문 요청은 `original-not-retained`로 끝난다. 원문이 있는 것으로 표시하거나 canonical YAML로 대체하지 않는다. 가져온 Vault 값·password/token·개인키·provider 응답은 원문에 추가하지 않는다.

## 요청

두 method는 SFCP User kind1이며 Unix·네트워크에서 같은 인증·payload를 사용한다. 현재 Session의 tenant Read scope와 현재 membership을 검사한 뒤 앱을 찾는다. 다른 tenant나 예상과 다른 deployment는 `denied`다.

다음은 선택자를 설명하는 예시다. 실제 signed Request의 공통 Nonce·canonical 필드 순서·Envelope는 [Unix API](unix-sockets.md)를 따르며 client 코어가 구성한다.

```json
{"Schema":1,"Method":"app-source","Tenant":"shop","AppSource":{"App":"store","Deployment":"deploy","Revision":0,"Part":0,"Digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}
```

| AppSource 필드 | 형식·의미 |
|---|---|
| `App` | 필수 string: tenant 안의 앱 이름 |
| `Deployment` | 선택 string: 예상 deployment ID. 지정하면 정확히 일치해야 함 |
| `Revision` | uint64: 원문 버전. 첫 part에서0이면 최신 수락 버전 |
| `Section` | 선택 `source`·`local-services`·`overlays`·`pending-local`. source는 원 Git/업로드 YAML, local-services는 그 버전의 별도 로컬 서비스 YAML, overlays는 CD 필드 덮어쓰기 JSON, pending-local은 `put-app-local-services`가 받아 다음 sync를 기다리는 로컬 서비스 YAML이다. pending-local은 Revision 0만 받고(버전이 아니다), 응답 `Pending{Revision,Actor,Length,Digest}`가 그 문서를 고정하며 Version은 최신 버전의 신원일 뿐이다. 기다리는 문서가 없으면 `section-unavailable` |
| `Part` | 0부터 시작하는 유한 part 번호 |
| `Digest` | SHA-256 `[32]byte`: JSON 정수32개 배열. 첫 part에서0 허용 |

Part가1 이상이면 Revision과 해당 Section의 Digest를 반드시 지정한다. 세 Section은 별도 digest를 가지며 섞지 않는다. source의 digest가 다른 버전에 동일한 내용으로 재사용됐더라도 버전 선택은 별개다.

overlays 또는 local-services가 없는 버전의 해당 Section 요청은 `section-unavailable`이다. 원문이 보존되지 않은 경우와 구분한다.

버전 목록 요청은 `Method:app-revisions`, `Tenant`, `AppSource:{App,Deployment?,Revision:0,Part:0,Digest:0}`, 선택 `After`를 쓴다. Section·원문 버전·part 선택자는 목록 요청에서 금지한다. Node·TargetUser·tasks 전용 App 필터도 두 method에 넣지 않는다.

## 응답과 한도

원문 응답은 `Schema:1, Code:ok, AppSource:{Section,Version,RootRevision,Part,Data}`다. Data는 JSON base64 byte string이며 part당 최대24KiB다. Version에는 원문·overlay 각각의 digest와 전체 길이가 있다. 로컬 추가분을 수락한 버전은 `LocalRevision`, `LocalActor`, `LocalDigest`, `LocalLength`도 가진다. 먼저 Version.Revision·Deployment·선택 Section의 digest/길이를 고정하고 part를 순서대로 모은 다음 전체 SHA-256을 확인한다. 읽는 도중 현재 배포가 바뀌어도 고정한 보존 버전만 읽는다. 현재 Read 권한은 각 요청에서 다시 검사한다.

원문 입력은 최대4MiB다. 원문을 포함한 Blueprint/upload 전체도 기존4MiB 한도를 적용하므로 정규화 설정·그래프·원문이 합쳐 한도를 넘으면 `PLAN_BUDGET`으로 계획을 거부한다. 앱 checkpoint 전체 한도16MiB와 앱별 최대128개 보존 버전도 유지한다. 한도를 피하려고 이전 버전을 자동 삭제하지 않는다.

버전 목록 응답은 `AppRevisions`, `AppRevisionsNext`, `AppRevisionsRootRevision`이다. 최신 버전부터 최대16개·행 JSON 합계64KiB를 반환한다. cursor는 Apps/Catalog/Members root·현재 사용자/서명 scope·tenant/app/deployment에 묶인다. basis가 달라지면 `conflict`로 거부하므로 빈 cursor에서 다시 읽고 이전 목록과 섞지 않는다.

| Version 필드 | 의미 |
|---|---|
| `Revision`, `Tenant`, `App`, `Deployment` | 앱별 원문 버전·소유 범위 |
| `Digest`, `Length`, `OriginalRetained` | 원문 SHA-256·바이트 수·실제 보존 여부 |
| `Plan` | 수락된 Blueprint digest. 원문 digest와 다름 |
| `SubmittedBy`, `Operation`, `AcceptedAt` | 제출 계정·원 배포 operation ID·고정 Unix초 |
| `CompletedAt`, `Status` | 실행 결과의 완료 시각·상태. 완료 전 시각은0 |
| `Source`, `Commit`, `Automatic` | upload/cd/move·알려진 Git commit·자동 CD 여부 |
| `OverlayDigest`, `OverlayLength` | 선택 CD 필드 overlay JSON의 digest·길이. 없으면0 |

CD 원문은 선택한 Git 바이트다. 로컬 추가 서비스는 Git 원문을 수정하지 않고 `local-services` Section의 별도 YAML로 보존한다. 이 Section은 RQ5의 로컬 추가분 목표 계약이며 작성 명령과 전체 수락 검증은 진행 중이다. 과거 버전 조회를 현재 추가분으로 대체하지 않는다. 명시 field override는 별도의 overlays Section으로 보존하며 원문에 합쳐 쓰지 않는다. 일반 사용자 업로드가 CD overlay의 과거 주체/권한 기록을 임의로 붙이는 것은 거부한다. overlays에는 공개 Path·Value·Revision·Actor만 있고 native 승인·credential·가져온 Vault 값은 없다.

이력 회수는 기존 `rotate-app-history`의 종료·quiescent·live binding 없음·원장 만료 조건을 그대로 따른다. 성공하면 보존 원문/overlay 목록도 회수하고 단조 버전 counter는 유지한다. 회수된 번호 조회는 `version-reclaimed`다. 앱 종료나 조회만으로 빌린 Volume/Secret/망과 원문을 삭제하지 않는다.

## CLI

```sh
sfcli --tenant shop manage app-revisions --app store
sfcli --tenant shop manage app-source --app store --raw > retrieved.app.yaml
sfcli --tenant shop manage app-source --app store --revision 1 --raw
sfcli --tenant shop manage app-source --app store --revision 2 --section overlays --raw
```

`--deployment ID`로 예상 배포 신원을 고정한다. 목록은 `--after CURSOR`로 잇는다. `--raw` 없이 원문을 요청하면 첫 part의 구조화된 응답을 출력한다. `--raw`는 고정한 모든 part와 전체 digest를 확인한 뒤 원 바이트만 stdout에 쓴다. 수정본의 배포는 기존 app deploy 경로를 사용하며, 원문 조회가 자동 재배포나 새 operation 발급을 하지 않는다.
