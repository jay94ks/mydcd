# 외부 이미지 저장소 정의

tenant 관리자는 기존 사용자 서명 관리 명령으로 외부 registry의 공개 자격 참조를 등록한다. 이미지 신뢰 출처와 자격 정의는 별개다. 자격 등록만으로 해당 registry를 신뢰하지 않는다.

## 관리 입력

`sfcli manage apply`의 JSON 변경 문서에서 `put-external-registry`와 `delete-external-registry`를 사용한다. 원 operation·서명·root CAS·결과/재개 규칙은 기존 관리 명령과 같다.

```json
{
  "schema": 1,
  "action": "put-external-registry",
  "expected": 0,
  "payload": {
    "Spec": {
      "Tenant": "payments",
      "ID": "ghcr",
      "Authority": "ghcr.io",
      "Repository": "my-org/**",
      "Enabled": true,
      "Auth": "token",
      "Credential": {
        "Realm": "payments",
        "ID": "registry-login",
        "UsernameKey": "username",
        "PasswordKey": "token"
      }
    }
  }
}
```

`Auth`는 `none`, `password`, `token`이다. `none`에는 Credential이 없어야 한다. 나머지는 Secret 객체의 두 키 이름을 참조한다. token은 registry 로그인에서 비밀번호 위치로 전달하는 토큰이며 별도 ECR 토큰 발급 기능이 아니다. 선택 `CA`는 `{Realm,ID,Key}`로 PEM Secret 키를 참조한다. Realm은 해당 tenant 또는 명시적 클러스터 전역 realm인 빈 문자열만 허용한다. 실제 읽기에는 별도의 기존 Vault 승인·권한이 필요하다.

`expected`는 해당 정의의 record revision이다. 최초 생성은0, 수정·삭제는 조회한 revision을 사용한다. 삭제 payload는 `{ "Tenant": "payments", "ID": "ghcr" }`다. 두 변경 모두 현재 ManageRegistry가 필요하며 tenant 종료 중 삭제는 cleanup 권한을 적용한다. Enabled를 생략한 put과 알 수 없는 필드는 입력 오류다.

authority는 scheme/path가 없는 정규 소문자 registry 주소다. 기본 포트 별칭을 임의로 동치 처리하지 않는다. 내장 registry가 사용하거나 보존하는 authority와 겹칠 수 없다. Repository는 정확한 경로, `prefix/**`, 또는 `**`이며 같은 tenant/authority/pattern을 여러 ID에 중복 등록할 수 없다.

선택은 정확한 repository, 가장 긴 subtree, `**` 순이다. 비활성/삭제된 정의가 선택되면 거부하며 더 넓은 정의나 익명으로 대체하지 않는다. 같은 ID의 authority/repository는 고정이다. 다른 범위는 새 ID로 등록하고 이전 정의는 명시적으로 비활성/삭제한다. 삭제는 원 참조와 revision을 보존하며 실행 중 컨테이너를 종료하지 않는다.

## 공개 조회

```sh
sfcli --tenant payments registry external list
sfcli --tenant payments registry external show ghcr
```

User method `external-registries`는 `{Schema:1,Method:"external-registries",Tenant,After?,Nonce}`를 받는다. 응답은 기존 Reply의 `ExternalRegistriesRootRevision`, `ExternalRegistries`(최대8개), `ExternalRegistriesNext`다. 행은 `{Spec,Revision,Deleted,Reader?}`이며 Reader는 `{Node,Owner,Generation,Draining}`만 담는다. 원 서명/Session·자격 값은 포함하지 않는다. 현재 tenant의 Read 또는 ManageRegistry 권한이 필요하다. 여러 페이지를 합칠 때 root revision이 달라지면 혼합하지 않고 처음부터 조회한다. CLI의 상세 조회도 같은 권한·페이지를 사용한다.

## 승인·값 공급과 실제 연결 범위

앱 계획은 선택한 자격/CA Secret 객체를 optional `RegistrySources`로 고정한다. 원 Secret Group 승인 절차를 사용하되 같은 Task Binding 안의 optional `RegistryGrants`로 독립된 인증용 사용 참조를 예약한다. Group 입력은 중복 요청하지 않으며 별도 인증용 consumer도 기존 승인 용량을 사용한다. 현재 인증용 grant 검사는 새 이미지 인증 경계에서 수행한다. 인증용 Secret의 회수가 앱 설정용 grant까지 무효화하거나 실행 중 컨테이너를 자동 종료하지 않는다. 이 보조 집합은 앱 Sources와 달리 파일·환경 변수 키셋에 합치지 않는다. 동명 키가 있어도 앱 값을 덮어쓰거나 컨테이너에 투영하지 않으며, 앱 종료는 원 Binding의 동일 종료/반환 경로로 두 종류의 참조를 정산한다.

`registry-image-permit`는 선택 참조 `External`과, 보호된 읽기가 필요한 경우 `ExternalInputs:{ReadSet,Entries:[{Realm,Leaf,Provider}]}`를 반환한다. 모두 공개 metadata이며 fetch 권한을 대신하는 bearer가 아니다. Runtime은 quorum barrier 이후 같은 로컬 상태와 대조하고 기존 SecretFetch로 정확한 leaf/reference를 읽는다. provider도 실제 Task/Binding과 현재 registry 정의를 다시 확인한다. 받은 값의 revision/키·예산을 검사하고 마지막 허가를 재확인한 뒤 해당 authority의 일시 Engine RegistryAuth로 전달하고 원 bytes를 지운다. password/token은 이 경로를 사용하며 자격 없는 `none`은 익명이다. 원 Task 수락 이후 새 자격 참조를 추가한 경우에는 그 Task의 오래된 승인으로 빌려 쓰지 않고 새 앱 계획·승인이 필요하다.

로컬 CD 추가분은 실제 작성자의 ACL을 보조 참조에도 적용한다. Volume 이관의 원 target 준비 역시 같은 source 선택 코어로 고정 참조와 현재 정의를 대조하며 회수·새 참조를 과거 승인으로 대체하지 않는다.

외부 인증은 `go-containerregistry`의 요청별 클라이언트에 자격과 CA를 고정한다. CA는 해당 호출의 인증서 pool에만 추가하고 호스트·Docker daemon 설정을 변경하지 않는다. HTTPS만 허용하며 다른 authority로 자격/header/인증 본문을 넘기지 않는다. Docker Hub의 공식 registry/auth host는 정규 docker.io source의 내부 주소로 취급한다. ambient Docker keychain·proxy·익명 재시도는 사용하지 않는다.

엔진(Seafield)은 registry에 직접 닿지 않는다. 고정된 ref가 엔진에 없으면 sfcd가 그 뿌리(`repository@sha256:…`, tag는 뗀다)로 pull ticket을 만든다. ticket은 이 요청별 클라이언트로 원 manifest/index와 그 아래 manifest를 읽어 graph를 적어 둔다. 그다음 sfcd가 엔진에 그 뿌리를 pull하라고 하고, 엔진이 묻는 manifest·blob(purpose 37)을 같은 클라이언트로 읽어 넘긴다. 엔진은 받은 모든 내용의 digest를 확인하고 실행 platform을 스스로 고른다. pull이 끝나면 ticket을 닫는다. 엔진에는 자격도 registry 주소도 가지 않는다. 끊긴 blob은 받은 만큼의 offset부터 다시 묻는다(지금 sfcd는 source에서 처음부터 읽고 그만큼을 버린다). 실제 Task는 엔진이 돌려준 native ID를 기존 Process recipe에 고정한다. `pull=false`는 새 pull을 하지 않는다. 관측 단계는 graph 읽기가 `resolve`, 엔진 pull이 `load`다.

metadata/config는1MiB, layer 합은10GiB, layer 수는4096개로 제한한다. 적재 stream에는 tar framing을 위한 별도 여유 한도만 추가한다. 입력·원 context와 socket idle 예산을 유지하고 오류/취소 뒤 원 upstream/pipe writer를 정리한 후 반환한다. 공개 오류에는 제한된 코드만 남기며 서버 body·URL·auth challenge·자격을 포함하지 않는다. 이 제한과 코드 연결은 실제10GiB push 성공의 근거가 아니다.

내장 registry의 Task 이미지도 같은 길로 받는다. sfcd가 Task에 서명한 로그인으로 그 registry authority를 직접 읽고(시스템 인증서 신뢰), 엔진에는 ticket으로만 넘긴다.

## 앱 없는 관리 source 승인과 로그인 시험

관리 source의 읽기는 앱 Task의 grant를 빌리지 않는다. 관리자가 source를 읽을 노드를 명시하여 기존 Vault Approvals의 사용 참조를 예약한다. source 정의 등록 자체는 Secret 읽기 승인이 아니다. `none` source도 관리 조회를 수행할 노드를 명시적으로 bind한다.

```sh
sfcli --tenant payments registry external bind ghcr --node node-a
sfcli --tenant payments registry external check ghcr
sfcli --tenant payments registry external check ghcr --image ghcr.io/my-org/app:release
```

bind에는 현재 tenant ManageRegistry와 지정 노드 Deploy 권한이 필요하다. CLI는 먼저 공개 계획을 읽는다. 그다음 원 source 지문·record/root CAS·epoch·사용자 서명을 저장한 뒤 필요한 Group 승인을 진행한다. Group 비밀번호는 터미널에서 묻는다(`--no-input`이면 실패). 동일 Group은 한 번만 요청하며 비밀번호를 operation에 저장하지 않는다. 최초 bind 예약은
원 operation.At 이후 현재 Vault에 commit된 해당 registry-source target의 서명 승인 fact를
소비한다. 모든 realm/Group이 함께 유효한 하나의 시각으로 기존 Acquire 검사를 수행하며,
뒤 승인 때문에 앞 승인의 최대 나이가 지났으면 거부한다. 원 bind operation·ID·서명은 유지한다.
이 시각은 최초 예약에만 쓰고 owner의 실제 읽기는 원 Grant.Pins와 현재 요청 시각으로
권한·철회·max-age를 다시 검사한다. 불명 응답은 같은 `--id`로 다시 실행하거나 `sfcli op resume ID`로 원 서명·선택을 그대로 보낸다.

관리 source 사용의 `Use.Purpose`는 `registry-source`이고, Group 서명 대상의 `purpose`도 같은 값이다. 이 승인의 actions는 `resolve,registry`이며 앱의 기본 `resolve,mount`와 호환되지 않는다. source와 앱이 같은 이름·사용자를 사용해도 승인·usage·종료 증명을 교환할 수 없다. schema는1이며 기존 purpose 없는 앱 서명 형식은 유지한다.

| User method | 입력 | Reply 필드 |
|---|---|---|
| `external-registry-bind-plan` | `Tenant`, `ExternalRegistryBind:{ID,Node}` | `ExternalRegistryBindPlan:{Schema,Cluster,Selection:{Tenant,ID,Node,Definition},Spec,Expected,RootRevision,Epoch,Uses}`. Uses는 realm별 공개 `secrets.Use` 목록이며 자격 값이 아님 |
| `registry-login-test` | `Tenant`, `ExternalRegistryProbe:{ID,Image?}` | `ExternalRegistryProbe:{Selection:{Tenant,ID,Generation},Owner,At,Code,Image?,Pull?}` |

두 method는 기존 User envelope/Session·Nonce·finite EOF를 따른다. Node/After나 다른 method의 selector를 섞지 않는다. bind 실행의 typed action은 `bind-external-registry`이고 payload는 계획의 `Selection`, expected는 계획의 `Expected`다. Vault Group 계획은 기존 `vault-approval-plan`의 `Origin`에 이 원 bind operation을 넣어 계산한다. 현재 조회 계정과 원 승인 요청자의 같은 user를 확인하며 실제 requester key·source 선택은 원 operation에 고정한다.

`registry-login-test`에는 현재 ManageRegistry 권한이 필요하다. 원 bind 사용자의 현재 역할·허용 노드·credential operation 제한, 정확한 Secret/ACL/Group 승인과 source 세대도 매번 검사한다. 다른 installed node를 통해 요청하면 원 사용자 Session과 선택을 실제 source owner에게 전달하며, owner/provider는 각각 현재 quorum 허가를 얻는다. 일반 tenant Read 권한은 관리 로그인 시험이나 Vault 원문 접근을 허용하지 않는다.

로그인만 지정하면 실제 HTTPS `/v2/` challenge를 확인한다. Image가 있으면 해당 source 범위 내 이름만 허용하고 tag를 immutable manifest/index digest로 해석한다. owner의 OS/architecture에서 선택한 config를 읽고 각 layer의 인증된 HEAD와 선언 크기를 확인한다. 응답 `Image`는 `{Normalized,Registry,Repository,Pinned,Digest,MediaType,ManifestBytes,Platforms?}`이며 config 원문은 없다. `Pull`은 `{ManifestDigest,Platform,Blobs,CompressedBytes}`로 선택 platform과 확인 범위를 표시한다. 전체 layer 다운로드·Docker 적재·실행 성공을 의미하지 않는다. 이미지 신뢰 정책이나 배포 권한도 추가하지 않는다.

성공 Code는 `OK`다. `UNAUTHORIZED`, `DENIED`, `NOT_FOUND`, `UNSUPPORTED`, `UNAVAILABLE`, `TIMEOUT`, `CANCELLED`, `PLAIN_HTTP`, `PLATFORM_MISMATCH`, `RATE_LIMITED` 등 레지스트리 클라이언트의 제한된 코드(`registryclient.ValidResultCode`)를 그대로 반환하고 실패 시 Image/Pull을 성공 근거처럼 남기지 않는다. `PLAIN_HTTP`는 source가 TLS hello에 평문 HTTP로 답할 때다. source는 HTTPS로만 읽으며 SDK의 HTTP 재시도는 쓰지 않는다. `PLATFORM_MISMATCH`는 선택한 config의 OS/architecture(/variant)가 owner와 다르거나 비어 있을 때다. 예를 들어 `crane append`로 만든 이미지가 그렇다. `UNSUPPORTED`는 지원하지 않는 매니페스트 media type이나 registry의 405/501 응답에만 쓴다. `RATE_LIMITED`는 registry가 429로 읽기를 막을 때다(Docker Hub는 익명 pull 수를 주소마다 제한한다). 엔진에 이미 있는 digest 이미지는 조정이 반복돼도 source를 다시 읽지 않는다. 이 재사용은 source 자격 증명을 다시 확인하지 않는다. 배포마다 sfc의 이미지 허가(trust 규칙, binding)는 다시 확인하지만, source 쪽에서 자격을 회수해도 그 로컬 이미지가 지워질 때까지는 같은 이미지를 계속 쓴다. `At`는 이 호출의 결과 시각이며 마지막 성공 이력을 내구 저장했다는 뜻이 아니다. provider 오류 body·URL·challenge·자격은 결과에 없다. CLI는 결과를 출력하고 성공은0, registry 시험 실패는3으로 종료한다. 정책/전송 실패는 기존 CLI 오류 규칙을 따른다.

## source 읽기 중지와 사용 참조 반환

빌드 begin의 서명된 Sources가 같은 reader 세대를 보유하면 owner RPC가 모두 종료됐어도
`external-registry-closed`를 수락하지 않는다. 원 job의 native/I/O 정리가 확정된 complete
이후에만 반환한다. 취소·unknown·source 폐기는 새 읽기를 막지만 이 참조를 없애지 않는다.
[빌드 source의 형식과 수명](image-build-jobs/04-owner.md)을 따른다.

`unbind-external-registry` payload는 `{Tenant,ID}`이고 expected는 현재 source record revision이다. 기존 `manage apply`로 실행한다. unbind/delete는 ManageRegistry cleanup 권한을 적용한다. source의 put·delete·unbind는 기존 reader를 Draining으로 전환하여 새 Secret/HTTP 읽기를 막는다. 이후의 명시 bind는 원 owner 종료 정산 뒤에만 가능하다. source 수정으로 기존 승인이나 실행 중 앱을 새 자격에 자동 연결하지 않는다.

owner는 원 source 세대를 로컬에서 fence하고, 진행 중인 Secret fetch·HTTP 요청/reader가 종료하고 일시 자격을 정리한 뒤에만 서명된 `external-registry-closed`를 보고한다. 정확한 세대·owner·grant/lifetime·purpose의 원 종료 증명으로 Vault 사용 참조와 reader를 같은 FSM 변경에서 반환한다. 응답 유실이나 관측0만으로 반환하지 않는다. 종료 보고는 source root CAS를 갱신하되 사용자가 보는 record revision은 변경하지 않는다. 원 Secret·삭제 흔적·종료 영수증은 보존한다. 살아 있는 reader는 노드 활동과 tenant 종료·원장 회수의 미정산 참조에 포함한다.

노드 간 source work는 `external-registry-work:{Selection:{Tenant,ID,Generation},At}`이며 `{Reader,Inputs:{ReadSet,Entries},Index,Epoch}`를 owner에게만 반환한다. 기존 SecretFetch의 `AppInputFetch`에 선택 `ExternalRegistry:{Tenant,ID,Generation}`를 사용한다. 이 경우 Move·Task·Binding digest는 비우고 Binding.At, Consumer, MinimumIndex, ReadSet, Realm, Secret은 정확한 현재 허가를 따른다. 이 메시지를 관리 Unix listener의 일반 사용자 읽기로 노출하지 않는다.

`sfcli image usages --source ID`/User `image-usages`의 ExternalSource selector는 이 정의에 매칭되는 현재 tenant의 앱/Task·보존 버전 참조를 읽는다. 비활성/삭제 후에도 같은 source 선택 코어가 원 정의를 보존하여 사용처가 익명으로 사라지지 않는다. 승인된 Secret reader의 현재 성공 여부나 실제 컨테이너 생존 count와는 별개의 선언 참조다. [행과 페이지 명세](image-usages.md)를 따른다.


## 실제 이미지 받기 결과 조회

`sfcli registry external pulls` 또는 User `external-registry-pulls`로 선택한 tenant의 최근 실제 받기 결과를 읽는다. 로그인 시험이나 layer HEAD 검사는 이 관측을 쓰지 않는다. 이미 존재하는 config를 재사용한 경우도 새 받기 성공을 만들지 않는다.

요청과 응답은 다음과 같다. `Schema`는 1이며 기존 Session/request proof·유한 User 요청의 EOF 규칙을 그대로 사용한다.

```json
{"Schema":1,"Method":"external-registry-pulls","Tenant":"payments","After":""}
```

`Reply.RegistryPulls`는 `{Schema,Tenant,Root,Index,Rows,Next}`다. `Root`는 기존 JSON 형식의 32바이트 배열이며 cursor는 서버가 반환한 불투명 문자열이다. 한 페이지는 최대 8행이다. `Rows`의 형식은 다음과 같다.

| 필드 | 의미 |
|---|---|
| Tenant, Authority, Source | 작업 공간·정확한 저장소 주소·실제 사용한 외부 source 이름 |
| Node | 이미지를 받았던 노드 |
| Stage | `resolve`: 받기에 필요한 원격 manifest/config 확인 실패, `load`: 실제 layer 다운로드·Docker 적재 단계 |
| Code | 성공 `OK`, 인증 `UNAUTHORIZED`/`DENIED`, 연결 `UNAVAILABLE`, 취소/기한 `CANCELLED`/`TIMEOUT`, 이미지·예산·적재 실패 등 제한된 코드 |
| CompletedAt | 실제 해당 결과를 얻은 Unix 밀리초. 관측 재전송·재시작으로 갱신하지 않음 |
| Sequence | 같은 노드의 tenant × authority별 내구 완료 순서 |
| ReportedAt, Stale | 해당 노드에서 관측을 보고한 Unix 밀리초와 기존 노드 관측 한도 초과 여부 |

노드마다 tenant × authority의 마지막 결과 하나를 기존 `observations.db`에 보관하고 기존 서명된 SFCP Report 경로로 전달한다. 공개 응답에는 노드 서명·자격·Vault 사용 grant·원격 body·header를 담지 않는다. `Stage=load,Code=OK`는 해당 시도에서 Docker 적재 후 config inspect까지 성공했다는 뜻이며 컨테이너 배포 성공을 뜻하지 않는다. 현재 저장소 가용성·로그인 허가·이미지 삭제 허가로 사용하지 않는다.

현재 tenant의 Read 또는 ManageRegistry 권한과 등록된 노드의 현재 키로 검사한다. 다른 tenant의 행·노드 서명·개인키는 반환하지 않는다. source가 변경/삭제되어도 원 결과의 Source 이름·완료 시각은 유지된다. 삭제된 노드나 교체된 키의 관측은 현재 키의 결과로 승격하지 않는다. 새 샘플을 못 받으면 이전 결과를 `Stale=true`로 반환할 수 있으며, 관측이 없으면 행이 없는 것이지 성공이 아니다.

현재 허가된 공개 행에 cursor를 고정한다. 페이지 사이 결과나 보고 샘플이 바뀌면 `conflict`로 처음부터 다시 읽는다. 무관한 tenant의 행이나 Raft index만 바뀌면 public root를 바꾸지 않는다. CLI는 모든 페이지를 모은 뒤 한 번에 출력하며 서로 다른 root를 섞지 않는다.
