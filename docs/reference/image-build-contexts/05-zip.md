## ZIP 전송과 버전 생성

owner의 native 회수는 기존 member Management `image-build-artifact-work`·`image-build-owner-report`를 사용한다. report는 `{Schema:1,Cluster,Owner,Tenant,Upload,Action,Expected,RootRevision,Epoch,Expiry?,Reclaimed?,Part?,Signature}`이며 Action은 `expired|reclaimed|part`다. part의 `Part:{Session,Proof,Receipt,At}`는 원 signed begin/scope 안에서 현재 사용자 서명과 owner의 실제 slot 영수증을 고정한다. 공유 part 지문/진행과 retained 승인 사실을 같은 기존 ModuleReport로 확정하며 generic 사용자 operation을 만들지 않는다. Session/Proof는 공개 metadata 페이지에 노출하지 않는다. Expiry는 원 scope·고정 관측 At·owner 서명이고, Reclaimed는 `{Schema:1,Scope,Version,Native,At,Signature}`로 실제 정리/반환 증거에 고정한다. Root/epoch·owner·원 upload revision과 현재 version 참조를 재검사한다. 현재 ledger 보고를 새 artifact 작업으로 해석하지 않는다.

```sh
mydc --tenant tenant-a build context upload source context.zip --id source-upload
# 끊긴 업로드는 같은 --id로 다시 실행하거나 op resume으로 이어 보낸다
mydc --tenant tenant-a build context upload source context.zip --id source-upload
mydc op resume source-upload
```

CLI는 최대500MB인 같은 파일의 전체 SHA-256을 먼저 구한다. 전역 `--timeout`은 파일 해시·조각 전송·seal/consume를 포함한 이 CLI 실행의 전체 기한이므로 큰 입력은 파일 크기와 연결에 맞게 명시한다. 기한 종료는 원 upload의 미실행/삭제를 뜻하지 않으며 같은 원 입력에 명시 `--resume`을 사용한다. 새 업로드의 generic 관리 journal은 원 `PREFIX-begin`과 `PREFIX-consume` 두 개다. 각 part는 현재 Session의 서명에 `Record:true`를 고정하고, owner의 실제 slot 영수증을 기존 `image-build-owner-report`의 `Action:part`로 공유 bitmap에 확정한다. part마다 UserOperation/journal을 만들지 않으므로500MB의32KiB15,259조각 또는 legacy24KiB20,346조각도 관리 ledger의256개 operation 한도를 소모하지 않는다. Raft에는 part bytes 대신 서명 사실과 고정 slot 지문을 기록한다.

새 begin이 아직 없을 때만 CLI가 현재 Session 전체(Approval 포함)의 JSON을 직렬화해8KiB 이하면 `ChunkBytes:32768`, 그보다 크면 생략/0을 선택한다. 기존 begin journal·공유 Scope가 있으면 그 원 ChunkBytes를 그대로 사용하고 양쪽 값이 다르면 거부한다. 재로그인이나 CLI 교체로 조각 크기를 다시 고르거나 원 begin을 재서명하지 않는다. User와 member Management owner/permit의 frame 상한128KiB는 유지한다.

CLI는 초기 조회에서 원 scope/revision을 고정하고 각 owner PartReceipt의 서명·scope/index/길이/지문과 `Recorded/UploadRevision`을 확인한다. Recorded ACK는 서버가 현재 사용자 proof·실제 native slot·공유 slot 확정을 모두 검사한 결과이며 그 UploadRevision을 다음 조각의 CAS로 이어 쓴다. 조각마다 upload/누락 페이지를 반복 조회하지 않는다. 기존 legacy part 작업의 정산 또는 stage-only UserOperation 뒤에는 공유 upload를 새로 조회해 cache를 갱신한다. seal 전에는 한 번 조회하여 원 전체 Scope·마지막 ACK revision·Received==전체 조각 수를 대조하고, 같은 열린 FD의 전체 길이/지문도 다시 확인한다. 충돌/권한 거부/불명 결과는 오류이며 CAS/root/서명을 자동 변경해 재시도하지 않는다. ZIP/part 원문은 journal/Raft에 넣지 않는다.

CLI는 작업 ID를 upload ID와 원 요청 prefix(`ID-begin`, `ID-part-NNNNN`, `ID-consume`)로 함께 쓴다. 기존 upload를 이어 가려면 원 `ID-begin` journal과 같은 파일·creator/context가 필요하다. 미완료 upload는 같은 `--upload-id`·`--request-id`·파일에 명시 `--resume`을 붙여야 하며 다른 prefix가 남의 원 상태를 채택하지 않는다. native part의 응답이 유실되면 자동 재전송하지 않는다. 명시 재개는 이미 공유 확정된 slot도 같은 scope/index/bytes로 owner에게 보내 원 inode/slot의 bytes를 확인하고 ACK를 회수한다. 누락 목록에 없다는 이유만으로 native 성공을 추정하지 않는다. 재개 때도 현재 Session·권한·proof 기한을 검사한다.

이미 존재하는 `PREFIX-part-00000` … legacy journal은 native 전송보다 먼저 원 result/resume 경로로 정산한다. 원 ID·receipt·CAS·epoch·서명·확정 실패를 보존하고 새 record로 대체하지 않는다. `Recorded:false`·`UploadRevision:0`인 stage-only 응답은 원 legacy per-part UserOperation 경로를 사용할 수 있다. 업로드 전체의 begin/part/consume가 기존256개 ledger 예산에 들어가지 않으면 명시 오류로 종료하며, 로컬 journal이나 서버의 남은 예산이 부족한 원 실패도 보존한다. 한도 상향·자동 epoch 회전·새 ID 발급·기존 기록 삭제로 우회하지 않는다. SDK의 `PutBuildZIPPart`는 record 인자를 생략하면 기존 stage-only 동작을 유지하며 bulk CLI만 명시 true를 전달한다.

User purpose8의 `build-zip-transfer` 요청은 `{Schema:1,Method,Tenant,ImageBuildTransfer:Transfer,Nonce}`다. Transfer는 `{Upload,Kind:"part"|"seal",Expected,Index?,Data?,Proof?,Record?}`이며 Data는 원 Scope의 조각 길이에 맞는 base64이며 `ChunkBytes:32768`은 최대32KiB, 생략/0인 legacy Scope는 최대24KiB다. optional Record는 true일 때만 직렬화하며 생략은 기존 stage-only false다. seal에는 Data/Proof/Index/Record를 넣지 않는다. 실제 canonical 본문은 Go Client의 marshal 순서를 사용한다.

part의 Proof는 `{Schema:1,Scope:[32],Index,Length,Digest:[32],Expected,At,ExpiresAt,Nonce:[32],Record?,Session?:[32],Signature:base64}`다. Record는 Transfer.Record와 같아야 하며 사용자 서명에 포함된다. Record=true의 Session은 독립 Approval을 포함한 현재 Session 전체의 도메인 분리 지문이며 relay가 더 넓은 credential로 바꾸지 못한다. stage-only는 Record=false·Session=nil을 생략하므로 기존 schema1 JSON/서명 표현을 유지한다. 사용자 Session.Key가 `mydc-imagebuild-part-request-1\x00`와 Signature를 nil로 한 JSON을 서명한다. 현재 creator·같은 scope/part/CAS/bytes, 최대120초와 Session 만료를 양쪽에서 검사하므로 설치 member의 relay가 다른 본문을 만들어 stage할 수 없다. 원 transport Session·사용자 승인 검사를 대체하는 node credential이 아니다.

성공 User Reply의 `ImageBuildIO`는 `{Schema:1,Scope:[32],Code,Part?,Seal?,Recorded?,UploadRevision?}`다. Code는 `OK|DIGEST_MISMATCH|INVALID_ZIP|STORAGE_UNAVAILABLE|CONFLICT`이고 OK일 때 요청 종류에 맞는 원 owner PartReceipt/SealReceipt만 있다. `Recorded:true`·양수 UploadRevision은 Record part의 정확한 shared slot까지 확정한 ACK이며 단순 native stage 성공과 구분한다. 같은 slot의 ACK 회수는 다른 slot 진행 뒤의 현재 revision을 반환할 수 있으므로 UploadRevision은 원 Expected 이상이며 항상 Expected+1이라고 가정하지 않는다. false/0은 함께 생략하고 기존 stage-only reply로 유효하다. seal/error에는 두 필드가 false/0이어야 한다. 관리 입구가 다른 노드면 기존 member MYDCP Management의 `image-build-owner`로 한 번 전달하며, owner는 quorum의 `image-build-io-permit`를 기록 전과 gate 대기 후·I/O 종료 뒤에 확인한다. Record part의 permit는 optional `RootRevision`으로 현재 보고 CAS도 반환하므로 같은 상태를 별도 artifact-work로 다시 읽지 않는다. 원 signed report의 Applied ACK가 확인되면 해당 upload revision+1을 즉시 반환하고, report 오류/ACK 유실일 때만 같은 현재 permit와 정확한 shared slot을 재조회한다. stage-only permit는 이 필드를 생략한다. 별도 비인증 RPC/HTTP를 열지 않는다.

owner는 등록 root의 원 durable pin과 Directory identity를 사용한다. 재시작의 기존 pin은 새 borrow 없이 원 fact로 reopen하고, 유실/교체 파일을 새 업로드로 초기화하지 않는다. 실제 fd/spool 종료 뒤에도 보존 artifact의 원 dependency는 native GC 전까지 유지한다. 마지막 조각은 전체 ZIP 지문을 검사하고 seal은 경로/링크/장치/CRC·Dockerfile·expanded 예산을 검사한다. 서명 확인 전의 부분 전송만으로 컨텍스트 버전이 생기지 않는다. 실제 builder와 전체 tenant/node 종료 조율은 별도 연결 범위다.


