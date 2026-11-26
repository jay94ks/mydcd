## 본인 자격 조회와 관리 사유

사용자 목록과 작업 공간 구성원은 [mydc user](../../cli/user.md)·[mydc tenant](../../cli/tenant.md)의 `list`·`members`로 본다.

`mydc manage self-credentials`는 현재 로그인 계정의 verifier 없는 공개 credential/계정 revision을 출력한다. 본인 key 변경은 기존 `manage apply`가 `add-credential`/`disable-credential` payload를 받아 처리한다. 다른 계정의 키는 `mydc user key add/disable`로 다룬다. proof·credentials scope·현재/원 Session·독립 승인·새 연결 재사용은 [client 인증](../../reference/client-authentication.md)을 따른다.


사용자 인증의 관리 명령에는 전역 `--reason TEXT`, `--incident-id ID`, `--approved-by ACCOUNT_ID`를 지정할 수 있다. 첫 원 operation을 만들 때만 서명 metadata로 고정하고, result/resume은 저장된 원 metadata를 보존한다. approved-by는 표시이며 승인 proof가 아니다. 로컬 profile/wallet 명령이나 node-key 인증을 사용자 operation으로 바꾸지 않는다. 예: `mydc --reason autofix --incident-id incident-1 --tenant shop manage apply --change change.json --request-id fixed-id`. credential 추가의 `--operations`는 [공개 계정 계약](../../reference/user-catalog.md)의 typed action 이름으로 제한한다.

### 앱 Secret 공급 선언

`app check/diff/deploy`는 [Secret 공급](../../reference/secret-delivery.md)의 `secrets` 파일 target과 `x-mydc.secret_env`를 같은 앱 입력으로 처리한다. `environment`는 일반 명시 값이고 같은 키의 Secret 환경 변수 선언과 겹치면 오류다. Secret 값은 CLI가 앱 파일에 확장하지 않는다. plan/diff의 `SecretEnvRequiresNewGeneration`에 열거한 서비스는 값/참조 교체에 새 Task 세대가 필요하다. 실제 환경 값은 Docker/컨테이너에만 공급하고 CLI 로그 조회는 서버에서 가린 결과를 받는다.

로그의 다음 페이지는 동일 옵션으로 `app logs APP SERVICE --cursor CURSOR`를 사용한다. `-o json`의 NextCursor 또는 일반 출력의 stderr 안내에서 cursor를 얻는다. `--follow`와 함께 쓰지 않으며, 만료는 CURSOR_EXPIRED로 명시 거부한다. [보관/출력 한도](../../reference/container-operations.md#로그-페이지의-원-구간)를 따른다.

실제 설정과 차이는 `app inspect APP SERVICE [--instance TASK --history N]`의 JSON으로 조회한다. frame별 기본 한도24KiB이며 큰 상세는 원 snapshot 전체를 검증/수집한 JSON으로 출력한다. logs/follow나 배포 옵션과 섞지 않는다. [필드·비밀값·검사 결과](../../reference/container-detail.md)를 따른다. 서비스 통계 시간 표본은 stats --watch로 client가 수집한다.

### Task 하나 재시작

`app restart APP SERVICE`는 원 대상을 확인하고 확인 질문(스크립트는 `-y`) 뒤 같은 native의 Stop/Start를 요청한다. `--instance TASK_KEY`는 논리 Task를 명시한다. `mydc op show ID`로 실제 진행을 읽는다. 같은 ID의 재실행은 원 journal/결과를 사용하며 현재 실행 시각에 맞춰 재계획하지 않는다. 사유 전역 옵션은 새 서명 operation에만 적용한다. 현재 RQ4 연결/검증 단계와 wire 필드는 [Task 재시작 계약](../../reference/task-actions.md)을 참조한다.

`node cordon/uncordon NODE --preview`는 현재 scheduling revision을 보여 준다. 변경은 `--expected-revision N --request-id ID`를 사용하고 첫 revision은0이다. `node status`의 `NodeLifecycle[].Scheduling`과 lifecycle node revision/epoch를 구분한다. [운영 조치](../../reference/task-actions.md#노드의-새-배치-제외복원)를 따른다.

`cd approve-candidate/reject-candidate APP --candidate SHA256 --request-id ID`는 CD 입력 결정이며 기존 Secret Group `cd approve`와 다르다. 전역 `--reason`은 원 서명 metadata에 보존한다. `--expected-revision`으로 strict CAS를 선택하고 원 journal의 재개는 `--resume-original`로 수행한다. 반려한 commit/digest는 일반 재조회로 살아나지 않으며 명시 replan으로 재고한다. [CD 후보 승인·반려](../../reference/cd-candidate-decisions.md)를 따른다.

### Raft 수동 유지보수

`raft compact --preview`로 시스템 관리자용 원 대상 계획을 조회한다. 실행은 `raft compact --operation ID --request-id ID`이며 `--nodes NODE,NODE`, `--mode keep|minimal`, `--retain N`, `--parallel`을 선택한다. 기본은 voter 대상·keep·순차·현재 leader-last다. `compact-status OPERATION [--after CURSOR]`는 원 노드별 결과를 페이지로 읽는다. 수락과 실제 SDK 완료를 구분하고 같은 request ID는 원 journal을 보존한다. `--resume-original`은 원 서명만 명시 재개한다. [유지보수 API](../../reference/raft-maintenance.md)에 권한·실패·실제 파일 크기와 논리 회수의 차이를 정의한다.

registry·이미지·빌드 명령은 [mydc registry](../../cli/registry.md)·[mydc image](../../cli/image.md)·[mydc build](../../cli/build.md)에 있다.

### 끊긴 Mesh 링크 복구

`mesh reconnect --node NODE --peer PEER --preview`는 최근 owner 서명 down 관측과 원 노드 쌍을 조회한다. 실행은 같은 선택과 `--operation ID --request-id ID`를 사용한다. 시스템 관리자·reconnect-tunnel credential 제한을 적용하며 살아 있는 경로를 닫지 않는다. `mesh reconnect-status OPERATION`으로 실제 결과를 읽고, 같은 원 요청의 재조회/명시 재개는 노드 선택을 생략한 `--operation ID --request-id ID [--resume-original]`을 사용한다. 새 요청에는 명시 노드 쌍이 필요하다. [Mesh 복구 API](../../reference/tunnel-reconnect.md)를 따른다.

### 노드 이미지 캐시

`node cache plan NODE [--images ID,...] [--after ID]`는 시스템 관리자용 owner 서명 관측이다. full sha256 ID 최대8개를 골라 `node cache delete NODE --images ID,... --operation ID --request-id ID`로 같은 사용/참조 검사와 원 journal을 거쳐 실행한다. `node cache status OPERATION`은 이미지별 확정 결과를 읽고 `--resume-original`은 같은 원 서명만 재개한다. prune-node-images credential 제한을 적용한다. 태그·축약 ID·force·전체 prune·Volume/registry GC는 입력하지 않는다. 사용 중/수락된 이미지 참조와 불명 결과의 상세 계약은 [노드 이미지 캐시](../../reference/node-image-cache.md)를 따른다.

`cd pause/resume APP --preview`는 실행과 같은 권한·충돌 조건을 읽기 전용으로 확인한다. 실행은 기존 `--request-id` 원 journal을 사용한다. 이전 버전은 `manage app-revisions`와 `manage app-source`로 보존된 원 입력을 선택한 뒤 현재 app diff와 새 명시 배포로 적용한다. [CD 조치](../../reference/cd-candidate-decisions.md#일시정지재개와-이전-버전)를 참고한다.

최초 비밀번호·토큰 발급은 `mydc user issue-password`·`issue-token`이다([mydc user](../../cli/user.md)).

`events [--since CURSOR] [--limit 1..100] [--app APP] [--node NODE] [--kind KIND]`는 현재 사용자·선택 tenant의 관측 이벤트를 읽는다. `--cluster-scope`는 system-admin 전체 범위이며 명시 tenant/app과 섞지 않는다. 반환 Cursor와 같은 filter로 이어 읽고 `CURSOR_EXPIRED`(종료3)에는 명시 재설정이 필요하다. `Incomplete`는 알려진 수집 누락이며 빈 페이지를 건강/이력 완전성으로 해석하지 않는다. [전체 메시지·종류·보존 계약](../../reference/events.md)을 따른다.

