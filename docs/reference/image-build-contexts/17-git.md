## Git 자동 빌드 제출

Automatic=true 컨텍스트의 성공 관측은 같은 sfcd에서 원 commit/tree의 Git archive 준비로 이어진다. 기존 GitSavePlan과 원 파일/Spool/RootManager·SavedGit 코어를 사용하며 원 정의·policy revision·commit에 대한 `auto-<48자리 hex>` ID를 고정한다. node-local observations DB에 원 계획을 먼저 저장하고 같은 ID의 재시도에서 commit·CreatedAt/ExpiresAt을 바꾸지 않는다. 부분 archive는 새 ID·truncate/rebuild로 덮지 않는다.

내부 member Management `image-build-automatic-git-report`가 저장 증거와 정확한 원 실행 의도를 제출한다. 입력은 `{Schema:1,Kind:"automatic-git",Cluster:[32],Owner:[32],Definition:[32],Tenant,Context,RootRevision,Epoch,At,StartedAt,Saved:SavedGit,Snapshot:[32],Signature:base64}`다. Definition은 원 accepted put-build-context의 OperationBytes SHA-256이다. 서명은 `sfc-imagebuild-automatic-git-report-1\0`과 Signature=null인 표준 JSON을 연결해 owner가 Ed25519로 작성한다. RootRevision/epoch는 기존 ImageBuildKey의 CAS다. StartedAt은 최초 승인/provider 준비 확인을 통과하여 제출할 빌드 의도의 시각으로 재시도에서 유지하며 At는 현재 보고 시각이다. 제출 전에는 같은 순수 FSM 계산으로 준비 여부를 확인하며, Group 승인 대기를 실행 시간으로 소비하거나 이 확인만으로 공유 상태를 저장하지 않는다.

Snapshot은 JobSpec에서 Number만 0으로 한 JSON에 `sfc-imagebuild-automatic-git-intent-1\0` 도메인을 붙인 SHA-256이다. 다음 version 번호는 FSM이 할당하므로 앞선 명시 수동 게시로 번호가 바뀌어도 원 archive·context/policy·목적 registry·태그 규칙·플랫폼·StartedAt은 변하지 않는다. 실제 수락된 job은 할당된 Number까지 포함한 기존 JobSpec.Digest를 사용한다. 두 지문을 native job/Secret 조회에서 서로 바꾸어 쓰지 않는다.

서버는 원 사용자 승인의 현재 계정/credential·put/publish/begin operation ceiling·ManageRegistry와 node/root 허가, 현재 context/policy/관측 commit/tree·archive 길이/지문/owner 서명을 검사한다. 로그인 세션 만료를 새 node 로그인으로 대체하지 않는다. 수동과 같은 JobPlan 검사를 사용하고 기존 closed archive·immutable version·다음 번호·queued job과 build Secret 사용 참조를 한 FSM 변경으로 확정한다. 누락된 provider/key·Group 승인·예산 검사 실패는 이 변경 전체를 거부한다. 원 사용자 승인 시각과 새 Secret 승인의 유효성 검사 시각을 구분해, 새 승인/ReadSet은 실제 자동 수락 At로 확인한다.

보호된 Secret Group의 승인이 필요하면 기존 Vault 승인 API의 Origin에 원 put-build-context operation을 전달한다. 현재 성공 관측·원 정의·policy revision으로 해당 auto job의 정확한 image-build purpose/consumer 사용 대상을 유도한다. 다른 commit·앱·registry-source의 승인을 빌리지 않는다. 계정/권한을 확인한 사용자만 승인할 수 있고 노드 보고는 Group 비밀번호 승인으로 인정하지 않는다.

수락 뒤 실제 build/push/로그·취소/종료는 기존 builder worker와 job API를 사용한다. job 조회의 optional Automatic=true는 이 경로에서 수락했음을 나타내며 queued를 실행 성공으로 표시하지 않는다. version의 At는 자동 게시의 실제 수락 시각이다. 같은 auto ID의 기존 job은 실행 중·성공·실패·삭제 상태 모두 새 자동 제출을 막는다. 다음 commit은 같은 컨텍스트의 이전 자동 job이 실제 terminal closure를 보고한 뒤 수락한다. retry/resume에서 원 시작 시각·archive 기한을 갱신하거나 실패를 새 ID로 숨기지 않는다. 전체 실제 사용자/SDK 성공과 Group 승인 만료·단절/재개·정산은 RQ6 마지막 검증 대상이다.
