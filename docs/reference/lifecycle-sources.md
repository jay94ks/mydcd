# Lifecycle 원본 검사·업로드·버전 읽기

원본 바이트와 module ZIP은 provider 노드의 기존 SourceStore에 보관한다. 공유 Catalog에는 기존 서명 `SourceFact`·이름/버전·사용 참조만 저장한다. 사용자 Session으로 Unix TLS/QUIC에 접속하며 웹 client가 노드 키나 별도 mesh member일 필요가 없다.

## 원본과 ZIP 업로드

User method `lifecycle-source-stage`의 Request는 다음과 같다. digest/Upload는 실제32바이트 배열이며 예제의 배열은 표시용 축약이다.

```json
{"Schema":1,"Method":"lifecycle-source-stage","Nonce":[0],"Tenant":"tenant","Node":"node-a","CheckerSource":{"Tenant":"tenant","Digest":[0],"Length":123,"SDK":1,"Modules":[]},"CheckerUpload":[0]}
```

`Node`는 생략할 수 있다. 현재 tenant 정책·node ACL·설치 상태를 만족하는 provider 중 접속한 노드를 우선하고 이후 노드 이름순으로 고른다. 원본은 UTF-8,1–256KiB다. `CheckerSource`는 SHA-256·바이트 길이·SDK1·정확한 module lock을 고정하며 `Modules`는 현재 `Resolver.Modules`의 정렬된 부분집합이다. `CheckerUpload`는 client가 보존하는 원 업로드의 nonzero32바이트 ID다. 새 ID로 실패/불명을 우회하거나 재시도마다 ID를 생성하지 않는다.

서버의 kind2 `continue` 뒤 기존 User kind4로 원 바이트를24KiB씩 보내고 EOF한다. request ID·Envelope digest·연속 offset·전체 길이/SHA-256·EOF를 확인한 후 검사한다. 원 provider는 바이트 수신 전에 기존 upload hold를 확보하고 현재 ManageServices·provider node 권한·`lifecycle-source-upload` credential ceiling·활성 정책을 quorum으로 확인한다. Entry와 provider가 다르면 원 사용자 Session·Body·서명을 보존한 기존 member relay를 사용한다. 노드 키로 사용자 승인을 대체하지 않는다.

module ZIP은 같은 User 연결에서 **별도의 유한 요청** `lifecycle-module-stage`로 보낸다. 위 Request의 Method를 바꾸고 `CheckerModule`에 root lock에 포함된 정확한 `ModulePin{Path,Version,Digest,Length}`를 추가한다. ZIP은 기존 검사·길이/SHA-256·tenant cache 예산과 최대64MiB를 따른다. 자동 다운로드·외부 resolver·현재 lock에 없는 버전 선택은 하지 않는다. 응답의 Node를 보존하고 나머지 ZIP/root에도 같은 provider·descriptor·Upload를 사용한다. 원본을 먼저 보냈는데 필요한 ZIP이 없으면 fact를 발급하지 않고 missing으로 응답한다.

최종 `Reply.LifecycleStage`:

```text
{
  Node, Owner:[32]byte, Descriptor:SourceDescriptor, Upload:[32]byte,
  Source?:SourceFact,
  Module?:ModuleFact,
  Diagnostics?:[{Line,Column,Message}]
}
```

source 성공은 `Source` 하나, module 성공은 `Module` 하나다. 진단 응답은 제한된 `Diagnostics`만 있고 Source/Module fact가 없다. 진단은 최대32개·메시지당1024바이트이고 줄/열은1부터, 위치 없는 진단은 둘 다0이다. 구문·package checker·단일 Check의 실제 SDK signature·허용 import/고정 module graph와 타입을 검사한다. 사용자 init·전역 초기화·Check는 실행하지 않는다. 타입 정보는 daemon에 포함된 기존 Yaegi whitelist/SDK의 선언 metadata와 선택된 source graph를 사용하며 배포 노드의 Go toolchain/GOROOT·사용자 GOPATH·module cache에 의존하지 않는다.

검사를 통과한 후 현재 정책을 다시 확인하고 기존 SourceStore에 sync한 다음 원 Upload에 고정된 SourceFact를 반환한다. 이 fact는 그대로 `put-lifecycle-script`의 `Source`로 사용할 수 있다. 이름 등록/CAS는 별도의 기존 관리 변경이다. 타입 검사 통과·SourceFact는 checker 실행/앱 health·compiled binary Ready의 증거가 아니다. 기존 `checker-source-stage`는 원래의 바이트 보관 계약을 유지하며 새 editor 검사를 했다는 뜻으로 사용하지 않는다.

## 불명 응답과 원 복구

전송 유실 뒤 자동 재전송하지 않는다. kind2 준비 응답의 Node·Owner·Descriptor·Upload는 원 provider 선택을 보존하는 metadata이고 성공 fact가 아니다. SDK는 준비 응답을 받은 후 결과가 유실되면 이 metadata를 오류와 함께 반환할 수 있다.

`lifecycle-source-recover`는 같은 Tenant·명시 원 Node·CheckerSource·CheckerUpload를 보내고 body 없이 EOF한다. `lifecycle-module-recover`는 같은 필드와 원 CheckerModule을 보낸다. 기존 hold/원 fact만 조회하며 source/ZIP·새 upload·검사 성공을 합성하지 않는다. 정책이 꺼졌어도 원 기록 복구 권한과 현재 Session은 검사한다. 새 source 등록이나 실행 권한은 별도 현재 정책을 따른다. recover의 fact는 이전 보관 사실이며 새로운 타입 검사 결과가 아니다.

공개 오류는 `denied`, `missing`, `invalid`, `unknown`, `unavailable`로 제한하고 provider DB 경로·원 오류문·계정/Secret 값을 노출하지 않는다. 정책 비활성화·다른 tenant/provider 권한은 거부하고, 저장 sync/전송 불명은 원 ID로 보존한다.

## 정확한 버전의 원문 읽기

```json
{"Schema":1,"Method":"lifecycle-source","Nonce":[0],"Tenant":"tenant","LifecycleSource":{"Name":"ready","Revision":7,"Offset":0}}
```

Revision은 이름 record CAS와 구분되는 **immutable source revision**이며0/latest는 받지 않는다. 현재 ManageServices·Session/credential ceiling을 검사하고 Catalog의 해당 버전에서 원 provider와 descriptor를 선택한다. 입력으로 provider/URL/host 경로를 받지 않는다. retired이지만 삭제하지 않은 버전은 읽을 수 있고 삭제 버전은 missing이다. 원 provider의 부재/전송·저장 오류를 성공이나 빈 원문으로 바꾸지 않는다.

`Reply.LifecycleSource`:

```text
{Tenant,Name,Revision,Offset,Total,Next,Digest:[32]byte,Data:[]byte}
```

Data는 최대24KiB 원 바이트이며 JSON에서는 base64다. UTF-8 code point가 페이지 경계에서 나뉠 수 있으므로 전부 이어 붙인 뒤 디코딩한다. Offset은0 또는 앞 페이지 Next(24KiB 경계), Next0은 마지막 페이지다. 매 페이지는 같은 원 source Digest·Total에 고정되고 provider가 actual bytes를 읽어 전체 digest를 확인한다. 최종 소비자는 EOF까지 합친 길이/SHA-256·UTF-8을 확인한다. SDK `Client.LifecycleSource`와 CLI는 전체 검증 후 `{Tenant,Name,Revision,Digest,Source:string}`을 반환한다.

내부 member Management `lifecycle-source-version-permit`은 `{Session,Tenant,Query,Source,Epoch}`를 현재 quorum/Catalog·버전/원 서명과 비교해 index를 반환한다. `lifecycle-source-version-owner`는 같은 원 read를 provider에게 전달하여 위 source page 또는 제한된 오류 코드만 반환한다. 각각 현재 권한을 읽기 전과 공개 전에 다시 확인하며 사용자 Unix 입력에서 member 전용 명령을 실행할 수 없다. SourceStore/기존 cache GC의 원 참조 계약을 유지하고 별도 source 사본·읽기용 DB를 만들지 않는다.

## SDK와 CLI

SDK는 `StageLifecycleSource`, `StageLifecycleModule`, `RecoverLifecycleSource`, `RecoverLifecycleModule`, `LifecycleSourcePage`, `LifecycleSource`를 제공한다. stage의 descriptor/Upload와 이후 Node를 그대로 보존한다.

```sh
mydc --tenant tenant lifecycle source module --source-file ready.go --modules lock.json \
  --module example.invalid/safe --file safe.zip --upload ORIGINAL_64_HEX --node node-a
mydc --tenant tenant lifecycle source stage --file ready.go --modules lock.json \
  --upload ORIGINAL_64_HEX --node node-a
mydc --tenant tenant lifecycle source recover --source-file ready.go --modules lock.json \
  --upload ORIGINAL_64_HEX --node node-a
mydc --tenant tenant lifecycle source read ready --revision 7
```

CLI는 `--upload`를 임의 생성하지 않는다. stage는 원 파일을 descriptor에 고정하고 진단만 반환하면 종료3, signed fact 반환은0이다. 별도 이름 등록·앱 배포는 실행하지 않는다. 기존 script put/result/resume의 원 wallet/journal·CAS 동작도 유지한다. Secret Vault의 키나 값은 source 입력/진단에 자동 포함하지 않는다.

설치 노드 키를 교체한 뒤에도 등록된 원 버전의 `SourceFact.Owner`·서명·원 upload token은 바뀌지 않는다. 버전 읽기와 원 upload 복구는 같은 물리 노드의 현재 멤버 키로 인증하고 기존 resource-owner 연결을 통해 원 저장 namespace를 읽는다. 과거 키를 TLS/세션 issuer/새 관리 명령 인증에 사용하지 않는다. 새 editor 전송은 현재 owner의 새 token을 사용하며 과거 namespace에 이미 있는 token을 현재 namespace에 다시 생성하지 않는다. 원 token이 없거나 namespace가 서로 충돌하면 조회 오류로 남기고 새 전송을 만들지 않는다.

원 Task/use와 compiler job의 source/cache 참조도 같은 구분을 따른다. artifact·compiled cache는 원 provider/fact/recipe와 원 job을 보존한 채 현재 멤버 경로로 읽으며, 원 builder의 종료 proof는 원 키의 서명을 유지하고 현재 키가 보고 봉투를 서명한다. 과거 cache namespace는 새 compiler의 배치 후보가 되지 않는다. 기존 로컬 Task의 compiled 실행은 원 Use·cache owner와 provenance를 그대로 유지하고, 현재 설치 키의 Work 권한과 두 owner에 대한 인계 관계를 확인한다. 원 소유 키를 다시 활성 멤버로 취급하지 않으며 격리·현재 정책 회수·Use 반환 뒤의 새 검사는 허용하지 않는다. 현재 정책·사용자·Task가 허용하지 않는 Start는 복구 조회로 허용되지 않으며, 원문/캐시 조회 실패나 키 교체가 미정산 job의 종료 proof를 대신하지 않는다.
