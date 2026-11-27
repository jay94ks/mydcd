## 최초 credential의 보호 메시지

User kind1의 `initial-credential-stage`/`initial-credential-observe`/`initial-credential-profile`은 현재 system-admin의 Session/challenge 서명과 InitialCredential 공개 선택자를 받는다. stage의 password만 선택 Secret byte[]를 사용한다. owner pin을 고정하고 relay/redirect를 금지하며 follower는 quorum-backed view를 읽는다. InitialCredentialFact와 첫 token의 private byte[] 응답, 공개 `issue-initial-credential` action payload·CAS·한 번의 반환/복구 규칙은 [전체 메시지·필드 명세](../initial-credentials.md#사용자-세션-메시지)에 있다. 일반 operation Result/이벤트에는 token/password를 넣지 않는다.

### 관측 이벤트 조회

User kind1 `events`는 공통 Session/challenge 서명과 `{Tenant,Events:{Tenant,App?,Node?,Kind?,After?,Limit?}}`를 받으며 `Reply.Events:{Schema,Items,Cursor,More,Incomplete}`를 반환한다. 바깥 Tenant와 내부 Tenant는 같아야 하고 다른 method·바깥 After/Node/App·보호 입력과 섞지 않는다. 현재 tenant Read/허용 노드 또는 cluster ManageCluster를 확인하며 일반 조회의 quorum/leader 전달을 사용한다. `CURSOR_EXPIRED`와 denied/unavailable을 구분한다. [각 메시지·Item/Target/Detail·이벤트 종류·source/보존](../events.md)에 전체 형식을 정의한다. member 전용 `event-receipt`와 Observation `node-events`는 Unix User method가 아니다.

`replan-app`의 payload는 `{Tenant,App,Target?}`이다. Target이 있으면 현재 후보·등록·정책/override·실행/종료 의도에 고정한 CAS이며 source fetch·health 관측 revision만으로 거부하지 않는다. Target을 생략한 기존 원 요청과 CLI의 명시 `--expected-revision`은 CD/root revision의 strict CAS를 유지한다. 현재 ManageCD·credential 동작 제한·quorum과 원 operation replay 규칙은 동일하다.

CD 조회의 행/값/분할 형식과 권한·cursor 계약은 [CD 이력·설정값·변경점](../cd-inspection.md)을 따른다. history/diff는 로그인 사용자 Read이며 별도 관리 변경·Secret 입력을 섞지 않는다.


### RQ5 순차 교체 상태

앱 조회의 AppView에는 optional `Replacement:{Wave,Waves,Node,Phase}`가 있다. Wave는1부터 시작하고 Phase는 `retiring`·`applying`·`complete`다. `complete`는 모든 노드의 교체 진행 조건을 통과한 상태이며, 앱 전체 배포 성공은 원 Operation의 실제 Finish로 별도 판별한다. 원 Operation.ID·Blueprint·resource별 request ID는 파동마다 바뀌지 않는다.

보존 중인 stage의 `Previous`는 원 claim/command/result/native와 원 승인·참조다. 이 값이 새 목표의 Command/Result를 대신하지 않는다. 원 owner의 현재 서명 관측은 원 native 신원으로 확인하되 현재 rollout의 Plan/Operation에 고정한다. 실제 삭제/종료 증명 뒤에만 원 tombstone CAS로 새 세대를 Prepare한다. 다음 노드 진행에는 새 목표의 결과와 신선한 health가 필요하다. 실패·Unknown·만료 관측은 다음 노드 변경을 허용하지 않는다.

내부 관리 SFCP `app-progress`의 `Action:"advance-wave"`는 설치된 활성 WorkKey의 서명 보고다. Tenant·App·원 rollout Operation·Expected Inventory revision·At/Epoch/basis를 기존 형식으로 고정하며 Key/Observation/Retire/Release/Volume payload는 없다. reducer는 원 사용자 grant의 현재 권한과 같은 Inventory의 positive closure·새 세대 health를 재검사한다. 이 보고는 새 사용자 승인/배포나 Unknown 재제출을 만들지 않는다. 관리 Unix 사용자 연결은 이 내부 노드 보고를 직접 호출하는 통로가 아니다.

파동 retirement의 `KeepExecution:true`는 같은 원 Execution을 보존한다. 원 claim·retirement ID·서명된 종료/삭제 결과와 파동 좌표가 함께 검증되며, 해당 필드를 지워 일반 전체 종료로 바꾸거나 종료 증명 없이 다음 파동으로 건너뛴 checkpoint는 거부한다. 교체하지 않은 Task의 Secret/Volume/주소 참조는 반환하지 않는다.


내부 Ingress 관측 계약: 기존 signed `app-progress`의 Observation에 optional `IngressBackends:[{Key,Generation,Revision}]`가 추가된다. 정확한 현재/held Task ref의 정렬·고유 목록이며 Ingress stage만 보낼 수 있다. listener 소유자가 실제 balancer의 신선한 정상 backend를 관측하여 작성한다. 다음 파동은 대상 새 Task health와 해당 새 ref를 모두 요구하고, 과거 ref나 listener의 단순 Ready를 새 세대 성공으로 해석하지 않는다. 빈 목록은 새 backend 준비를 증명하지 않는다. 사용자 Unix API의 신규 명령이나 실행 승인이 아니며 기존 node report/원 operation·tenant·WorkKey·CAS·사용자 grant 검증을 유지한다.


### RQ5 `begin-app` 대상 CAS

기존 plain 앱 갱신에는 `AppView.BeginTarget`을 `AppBegin.Target`에 고정할 수 있다. `Expected`는 읽은 inventory revision floor이고 `UserOperation`은 그 원 root/epoch/ID와 Target을 함께 서명한다. 유효한 Target이 있는 요청만 기존 `ModuleAppCAS` kind를 사용한다. 지문은 원 Origin/sync, Scope, down/pending 의도, 원 active operation/plan/status, retirement, task restart/log clear 의도를 포함하며 health sequence/시각과 완료 시각·독립 upload revision은 제외한다. 현재 Target 일치와 미래 좌표 거부 뒤 같은 reducer가 원 Blueprint·현재 권한/배치/quota/소스·writer/retirement를 다시 검증한다. CAS가 native 종료나 가용성을 보장하지 않는다.

`sfcli app deploy`는 기존 plain 앱의 BeginTarget을 artifact/expected/epoch와 같은 로컬 intent에 보존하며 upload 전후나 resume에서 다시 선택하지 않는다. 신규 앱은 expected=0과 cluster/tenant/app/deployment별 부재 Target을 함께 고정한다. 서버는 해당 앱 entry가 여전히 없을 때만 수락하며 다른 앱의 checkpoint로 root만 바뀐 경우 현재 Blueprint·권한·배치·quota·소스를 다시 검증한다. 부재 지문은 `SHA-256("sfc-app-create-target-1\x00" || JSON({Cluster,Tenant,App,Deployment}))`이며 필드 순서와 대소문자는 이 순서대로, Cluster는 32바이트 정수 배열이다. 기존 앱에 expected=0으로 적용할 수 없으며 CD 앱도 덮어쓸 수 없다. Target 없는 과거 intent/서명은 기존 엄격 root/inventory CAS를 유지한다. 거부/불명 뒤 새 Target·서명·ID로 자동 재제출하지 않는다.

순차 교체의 내부 signed Observation에는 optional `IngressDrained:[{Key,Generation,Revision}]`가 있다. IngressBackends/IngressDrained는 원 Step.Identity/Goal.Follow의 복제본만 담으며 고정 backend의 관측·health와 구분한다. listener owner가 해당 원 Task 세대의 신규 요청 차단과 진행 중 HTTP lease의 내구 반환을 확인한 양의 사실이며, health 목록의 부재와 다르다. 정렬·고유·원 Task ref와 서명을 검증하고 해당 원 ref가 serving 목록과 동시에 존재하면 거부한다. Inventory는 이 사실 전에는 파동 Task의 첫 Drain을 dispatch하지 않는다. 기존 listener와 그 보존 중인 producer의 exact noop 준비·관측만 retirement 중 허용하며 listener 생성/변경은 허용하지 않는다. 이미 dispatch한 원 Drain의 Unknown/proof/delete 정산은 유지한다. nil 필드는 생략해 기존 schema1 서명 bytes를 유지한다. 관리 Unix의 사용자 호출 메시지를 추가하는 계약이 아니다.

외부 source의 bind/unbind와 로그인 시험 메시지의 전체 입력·응답·실패/종료 범위는 [외부 registry API](../external-registries.md#앱-없는-관리-source-승인과-로그인-시험)를 따른다. 기존 서명 operation·finite EOF·SecretInput의 보호 입력을 재사용하며 node 전용 work/SecretFetch/종료 보고는 Unix User 메시지로 허용하지 않는다.

User `image-resolve`의 전체 메시지·진단 코드·반환 예산은 [이미지 참조 확인](../image-resolution.md)을 따른다. 원 관리 권한이나 credential 발급 없이 내장 owner Store 또는 승인된 외부 source reader를 사용한다. node 전용 `image-resolve-owner`는 이 Unix listener의 dispatch 대상이 아니다.

User `image-usages`의 참조 범위·행/Match 형식·동일 root cursor와 오류는 [이미지 사용처](../image-usages.md)를 따른다. 원 Task/Inventory·CD·직전 버전의 선언을 읽으며 native 생존 상태나 삭제 허가를 대신하지 않는다.

외부 source의 실제 pull 결과·제한 코드·완료/보고 시각·페이지 형식은 [실제 이미지 받기 관측](../external-registries.md#실제-이미지-받기-결과-조회)을 따른다. 로그인/HEAD 시험·캐시 재사용은 실제 다운로드 성공으로 기록하지 않는다.

User `registry-catalog`의 repository/이미지 행·게시 시각·Live/untagged 한계·cursor는 [Registry 이미지 목록](../registry-images.md)을 따른다. 조회를 위해 별도 registry 자격을 사용자에게 발급하지 않는다.


Registry maintenance의 선택 External=true는 승인된 외부 source를 선택한다. 서명 target에는 원 reader 세대/정의·승인 ReadSet을 고정하고 내장 Run과 혼합하지 않는다. 외부 digest DELETE는 원 응답으로만 종결하며 401/403은 DENIED, 405/501은 UNSUPPORTED, 전송 후 응답 유실은 Result 없는 unknown이다. unknown의 원 이미지 fence는 유지하며 다른 source ID·새 원 작업으로 우회하지 않는다. 실제 source I/O join과 원 reader closure는 원격 효과 정산과 별개다. [전체 형식·단회 전송·종료 코드](../registry-maintenance.md#외부-registry-삭제)를 따른다.

일괄 이미지 정리는 [prune 메시지·행·조건·서명·원 결과](../registry-maintenance.md#일괄-정리)를 따른다. 큰 preview는 owner observations DB에 두고 User action에는 작은 조건/서명 fact만 넣는다. 내부 owner 전달은 원 사용자 Session을 보존한 Management registry-prune-owner이며 인증·tenant·현재 run/read-set 검사를 우회하지 않는다.


