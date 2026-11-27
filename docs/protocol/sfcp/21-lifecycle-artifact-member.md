## Lifecycle artifact의 member 소비

CheckerArtifact(13)는 schema1의 추가 purpose이며 QUIC member stream 전용이다. UserAuth/Read/Manage 또는 joining Replicate만으로 사용하지 못하고 Unix/relay/datagram/early data를 허용하지 않는다. VolumeTransfer의 archive 정렬/대용량 복구와 SecretFetch의 값 읽기 경계는 재사용하지 않는다. transport의 동시 수신 slot은2개다.

cache metadata의 `checker-cache-observe`는 기존 signed Management kind16(read)의 node-local read(Latest=false)다. 현재 member caller/consumer·원 app Use·Lookup의 provider와 고정 recipe를 결합하며 provider가 내부에서 현재 member/latest quorum의 checker-artifact-permit를 얻는다. Lookup은 Module/Compiled body 선택과 배타적이며 body purpose13에서는 거부한다. 응답은 schema1·cluster/provider/use/content/recipe/index·Found/CanBuild·optional CompiledFact다. Found=true는 실제 bytes와 원 closed provenance를 확인한 fact, Found=false는 양성 missing만 뜻한다. 오류/무응답/손상·원 origin 불명은 negative 응답이 아니다. CanBuild는 현재 local target/spawn 힌트이며 관리 확정·실행 권한이 아니다. consumer도 응답 scope/fact/current quorum 허가를 대조하며 metadata로 자동 compiler job을 만들지 않는다. 실제 bytes는 기존 purpose13으로만 전달한다.

| kind | 내용 |
|---|---|
| 1 | schema1 request: bounded Metadata·원 bytes digest/길이·최대300초 expiry, request JSON hash |
| 6 | 요청 쪽: 같은 원 digest/request hash의 request-end marker. ACK 방향은 열어 두며 추가 round trip 없이 kind1 뒤 전송 |
| 2 | 검증한 provider SourceFact/ModuleFact/CompiledFact 중 하나·원 request hash. metadata 검증 뒤만 body buffer 할당 |
| 4 | 정확한 offset8·최대24KiB chunk·원 request hash |
| 6 | provider 쪽: 정확한 전체 bytes digest·request hash의 body-end |
| 7 | 수신 node가 전체 bytes 검증/실제 저장 callback을 끝낸 뒤 같은 digest/hash ACK·write EOF |
| 8 | provider의 현재 허가 재확인 뒤 같은 digest/hash 최종 receipt·write EOF |

request metadata는20KiB, provider metadata는20KiB, body는64MiB 이하이며 실제 root256KiB/module64MiB 한도는 소유 어댑터가 원 descriptor와 대조한다. producer는 전송 전·256KiB 이내 window 경계·body-end·최종 receipt에서 현재 use/source/policy를 재검사한다. 매 frame의 current peer admission도 유지한다. receiver는 원 provider 서명·cluster/tenant/content/module을 대조하고 실제 local 저장 전에 같은 quorum permit을 재검사한다. 일부 수신은 실행/저장 성공이 아니며 Store 뒤 ACK/receipt 유실은 원 cache가 이미 존재할 수 있는 불명이다. transport는 재시도/redirect/새 입력 또는 job ID 발급을 하지 않는다. 다음 판단은 동일 local descriptor/pin의 확인과 원 workflow 정산을 사용한다.

checker-source-permit와 checker-artifact-permit는 기존 인증된 Management의 member/latest quorum reader를 사용한다. 일반 User metadata 조회로 바꾸거나 복사한 Use/SourceFact를 bearer token으로 취급하지 않는다. 실제 Runtime은 원 app Binding/Task·현재 user/node·source lock을 확인한다. build-job source 소비는 같은 checkpoint의 원 job/app parent·compile=true Task projection·현재 builder/정책/기한을 추가 확인한다. compiled 소비는 app use에서만 허용하고 현재 Task의 compile=true source와 수락 당시/현재 image·toolchain·target, 원 closed job의 input recipe 및 closure에 확정한 binary hash/길이를 대조한다. 과거 builder 서명만으로 새로운 bytes를 허가하지 않는다. CompiledFact의 현재 cache provider와 CompiledBuild의 과거 builder를 구분하며 양쪽 현재 member 허가는 consumer/cache provider에 적용한다. root/module은 기존 source provider의 현재 member 허가를 유지한다. metadata의 Module/Compiled는 배타적이고 원 builder/job 서명을 receiver의 cache 서명으로 바꾸지 않는다. compiled body도64MiB 이하이며 Store의 실제 hash/길이/ELF/내구 cache 검증 뒤 ACK한다. source/job producer·cache 선택·실제 검사 exec/Ready는 별도 제품 소비 경계다.

`checker-probe-permit`도 기존 Management kind16(read)의 member/latest quorum read다. 원 coordinator/provider·accepted 앱 Binding/원 dispatched run·같은 namespace·현재 양쪽 권한/정책·신선한 서명 native 관측을 확인하고 call ID/typed payload hash·대상·기한에 한정한 metadata를 반환한다. Request를 중복하지 않는 Run 입력은68KiB 이하이고 At은 Unix 밀리초·30초 범위다. 중첩 signed frame128KiB와 기존 private Probe 프레임 예산을 혼합하거나 전체 Management 한도를 늘리지 않는다. private IPC의 ProbeCall 자체는 인증 node RPC 권한이 아니며 provider는 실제 payload·자기 native/A3·자격 epoch를 별도로 확인한다. 실제 호출 전송·저장/불명/조회·closure 연결은 L1의 별도 소비 경계이며 이 판정 성공은 원격 실행 성공이 아니다.

`checker-shutdown-permit`는 같은 Management kind16(read)의 member/latest quorum read다. 원 owner/Binding/Task와 retirement operation/revision·미전송 drain 및 현재 권한/정책을 확인하며 일반 app-binding-permit의 retirement 거부를 완화하지 않는다. optional compiled fact는 원 Task의 compile=true·기존 closed provenance를 대조할 뿐 bytes 전송/build/Start 권한을 만들지 않는다. 요청 시각은 기존30초 범위, 자체 schema/SDK 번호는1이며 새 purpose·비인증 RPC를 추가하지 않는다. 검사 fail/unknown·중단과 실제 native 종료/참조 정산은 구분한다.

`checker-build-report`는 기존 Management kind16(read)의 member/latest 서명 module 요청으로 reserve/dispatch/close를 같은 ModuleReport ledger/FSM에 적용한다. 원 job과 source/policy pin은 같은 checkpoint다. `checker-build-permit`도 kind3의 member/latest quorum read이며 원 builder·job digest·minimum index·명시 시각·Start/Recover 배타성을 검사한다. Start는 원 dispatched job의 현재 Task/권한/정책·기한을 요구하고 Recover는 원 기록 확인용이다. intent48KiB·report64KiB 이하를 유지해 기존 Management128KiB frame과 명령64KiB 예산 안에서 전달한다. source/binary를 report에 넣거나 별도 TCP builder RPC를 열지 않는다. 실제 Docker journal/종료와 compiled 전송의 성공은 이 codec/수락 코드만으로 입증하지 않는다.

closed build permit에는 원 `BuildClosure`의 signed JSON digest를 선택 Closure 필드로 반환한다. node는 종료 보고 응답이 유실되면 같은 job/digest를 먼저 조회하고 일치하는 closed면 재제출하지 않는다. active의 같은 종료 사실 보고에는 현재 root/job CAS를 사용하며 원 native operation을 생성/재실행하지 않는다. cache의 `CompiledBuild`(원 builder)와 `CompiledFact`(실제 cache node)는 별도 서명이며 임의 provider/실행 grant로 취급하지 않는다. 현재 collector/저장은 node DB 경계이며 원격 compiled binary의 인증 전송과 소비 허가를 별도로 연결해야 한다.

lifecycle helper/compiled CLI의 상속 Probe FD는 원 run의 로컬 IPC다. FD3의 Request digest/순번/기한·bounded frame과 FD4의 결과를 D6 실행 Contract로 정의하며 새 네트워크 listener나 SFCP 우회 RPC를 열지 않는다. 원격 Probe/산출물 소비가 필요하면 현재 Task/원 job 권한을 검사하는 인증 SFCP 어댑터에 연결해야 한다. 로컬 FD codec/CLI 생성만으로 원격 compiled artifact 전송이나 native 실행을 허가하지 않는다.

### User app source 준비와 큰 계획 입력

AppPlanRequest의 PrepareSources/SourceProvider는 읽기 전용 preflight다. 현재 lifecycle capability와 실제 provider의 source permit을 확인하고 원 문서 hash/cluster/user/tenant·alias별 정확한 descriptor를 반환한다. source 저장·named 등록·compiler 기동·app mutation을 하지 않는다. 실제 bytes는 기존 checker-source-stage/recover와 checker-module-stage/recover로 준비한다.

기존 app-plan-stream의 SourceEnvelope=true는 원 문서와 source 사실을 함께 보내는 canonical body 형식이다. 기존 서명 metadata의 AppPlanInput.Length/Digest는 전체 body를 가리킨다. 원 문서4MiB·source facts128개/합계2MiB·개별16KiB·envelope8MiB를 제한하며 기존 raw 문서 형식은4MiB 그대로다. source 사실은 큰 request header에서 분리하고 같은24KiB ordered chunks/hash/EOF·권한 선검사/재확인·member relay를 사용한다. leader가 canonical envelope와 사실별 서명/cluster/tenant를 검사한 뒤 source 사실과 원 문서를 분리한다. wire 전용 SourceEnvelope는 control 계획 호출 전에 제거하며 직접 plan/move 요청으로 이 플래그를 재해석하지 않는다. schema 번호는1이다.

### lifecycle source 업로드의 회수 보호 metadata

User source/module stream의 signed Request에는 optional CheckerUpload(original intent signature의 domain-separated SHA-256)를 넣는다. 새 수신기는 bounded bytes를 받기 전에 tenant/descriptor/원 token의 UploadHold를 내구 저장하고 stream join 뒤에만 메모리 보호를 반환한다. SourceFact의 optional Upload는 같은 token을 node 서명에 포함하며 content digest·SDK·schema1을 바꾸지 않는다. recover는 같은 descriptor/token의 조회이고 hold 생성/새 전송/재로그인 ID 교체가 아니다. token 없는 legacy 요청/원 서명 bytes는 유지하며 원 작업이 입증되지 않은 cache는 보존한다. 등록/Use 수락과 같은 FSM 변경의 compact Publications 영수증은 원 tenant/owner/token→content digest를 snapshot 뒤에도 보존한다.

내부 Management kind16(read)의 checker-cache-gc-fence는 installed member·Latest quorum 전용이며 payload는 없다. 응답은 schema1·cluster/owner·index/epoch/lifecycle root revision이다. node collector는 같은 root의 로컬 catalog와 현재 index를 대조하고 원 업로드·등록/앱/build·로컬 미정산 실행·stream을 보호한 뒤 실제 blob 값을 sync 삭제한다. quorum 불가면 보존하고 이 fence로 새 스크립트/native 실행을 허가하지 않는다. 원 build/collection 서명과 explicit compiled eviction marker는 남겨 과거 수집 성공과 현재 cache missing을 구분한다. 상세 quota/수명은 D6를 따른다.

