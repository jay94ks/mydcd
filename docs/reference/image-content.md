# 이미지 manifest·config·layer 읽기

현재 tenant의 Read 또는 ManageRegistry로 고정된 이미지의 내용을 읽는다. 내장 Store, 승인된 외부 registry reader, 자격 정의가 없는 trusted 익명 HTTPS source를 같은 신뢰·원 사용자 경계에서 선택한다. Vault 자격·CA·새 pull/push credential을 호출자에게 반환하지 않는다.

```sh
# 원 바이트는 새 0600 파일에, stderr에는 검증된 공개 정보만 출력한다.
sfcli --tenant payments image pull-content registry.example/team/app@sha256:ROOT_DIGEST \
  --kind manifest -O manifest.json

# manifest의 config/layer descriptor에서 읽은 digest를 지정한다.
sfcli --tenant payments --timeout 5m image pull-content registry.example/team/app@sha256:IMAGE_DIGEST \
  --kind layer --digest sha256:LAYER_DIGEST -O layer.bin
```

예시의 digest는 실제64자리 SHA-256 hex로 바꾼다. config도 `--kind config --blob-digest ...`로 읽으며 config JSON에 history가 포함된다. root가 index이면 먼저 manifest를 읽고 원하는 child manifest의 digest를 Ref로 사용한다. tag·임의 URL·별도 blob 경로를 입력하지 않는다. 해당 manifest에 없는 config/layer digest는 blob 요청 전에 거부한다.

FD는3 이상인 pipe/socket 또는 현재 Linux user 소유의 private regular file이다. pipe/socket은 write deadline을 지원해야 한다. CLI는 복제한 FD만 닫으며 원 FD를 소유하지 않는다. regular file은 성공 후 fsync한다. 받은 원문을 stdout·공개 진단 JSON으로 출력하지 않는다. consumer writer는 caller context/취소를 준수해야 한다.

## SFCP 메시지

일반 User8 JSON method와 구분하여 **ImageContent 목적16**을 사용한다. schema/ABI는1이며 Unix TLS와 QUIC에서 동일하다. 공통24바이트 header와 TLV/LE 규칙은 [SFCP](../protocol/sfcp.md), 로컬 TLS record는 [Unix API](unix-sockets/23-purpose16.md)를 따른다.

| Kind | 방향 | 필수 TLV | body 한도 |
|---|---|---|---|
| 1 | 사용자 → 서버 | 1=Envelope JSON, 2=SHA-256(Envelope JSON),32바이트 | 128KiB |
| 2 | 서버 → 호출자 | 1=ImageContentReply JSON, 2=원 요청 Envelope digest | 128KiB |
| 3 | 설치 member → 원 owner | 1=원 사용자 proof를 보존한 Relay Envelope, 2=해당 Envelope digest | 128KiB |
| 4 | 서버 → 호출자 | 1=offset u64 LE, 2=최대24KiB 원 바이트, 3=원 요청 Envelope digest | 24KiB+64바이트 |
| 5 | 설치 builder member → 원 source owner, QUIC | 1=수락 빌드 본문 읽기 Envelope, 2=해당 Envelope digest | 128KiB |

Envelope는 기존 `{Body,Session,Signature,Relay?}`다. Body/Signature byte slice는 JSON base64,32바이트 배열은 JSON 정수 배열이다. Body를 풀면 다음 형식이다.

```text
ImageContentRequest {
  Schema: uint8 = 1,
  Tenant: string,
  Query: { Ref: string, Kind: string, Digest: string },
  ExpiresAt: int64,
  Nonce: [32]byte
}
```

- Ref는 정규 `authority/repository@sha256:<64 hex>`다. Kind는 manifest/config/layer다.
- manifest의 Digest는 빈 문자열이다. config/layer의 Digest는 Ref의 manifest가 직접 가리키는 SHA-256 descriptor다. config/manifest는 최대1MiB, layer는 최대10GiB이며 이미지 descriptor의 전체 용량 제한도 유지한다.
- ExpiresAt은 Unix 초이며 현재부터 최대900초, 원 Session 만료 이내다. 새 Nonce를 사용자 request proof에 포함한다.
- body 뒤 클라이언트 쓰기 EOF를 보내고 서버 응답을 읽는다. 응답 예산을 얻기 위해 별도 사용자 operation이나 journal을 만들지 않는다.

응답은 `{Schema:1,Code,Info?}`다. ready와 최종 ok에는 `{Schema:1,Ref,Kind,Digest,MediaType,Bytes}`의 Info가 있고 두 Info가 같아야 한다. denied/unavailable/unsupported/invalid/target-changed에는 Info가 없다. 원격 오류 body·Authorization·자격·CA 원문을 응답에 넣지 않는다.

ready 뒤 data offset은0부터 정확히 이어져야 하며 선언 Bytes를 넘기지 않는다. 서버와 client 모두 전체 본문의 길이·SHA-256을 확인한다. **전체 길이/지문, 최종 ok, 서버 EOF가 모두 맞아야 성공**이다. 일부 원문은 그 전에 전달되므로 파일·layer 목록 cache를 성공으로 공개하는 시점은 호출자가 최종 성공 뒤로 둔다. 단절·부족/추가 바이트·지문 불일치·마지막 권한 회수는 성공이 아니다. SDK `ReadImageContent`도 같은 계약이며 자동 재접속/재시도/이어 받기를 하지 않는다.

## 수락된 빌드의 FROM 본문

kind16은 수락된 빌드가 고정한 FROM의 본문을 읽는 내부 실행 경계다. 현재 설치된 builder member가 원 source owner에 직접 QUIC로 요청한다. 일반 사용자·Unix listener의 kind16 요청은 거부한다. 별도 사용자 관리 명령이나 새 session을 발급하지 않으며, 원 job의 signed begin·현재 job/권한·원 source reader 세대/ReadSet을 다시 검사한다. 원 로그인 session의 만료가 이미 수락된 job의 권한을 대신 결정하지 않는다.

Envelope는 `{Body}`이며 Session/Signature/Relay는 없다. Body는 다음 JSON을 base64로 담는다.

```text
ImageBuildBaseContentRequest {
  Schema: uint8 = 1,
  Read: {
    Read: ImageBuildBaseRead,
    Query: { Root: string, Path?: []string, Kind: string, Digest: string }
  },
  ExpiresAt: int64,
  Nonce: [32]byte
}
ImageBuildBaseRead {
  Cluster: [32]byte, Builder: [32]byte,
  Query: {
    Tenant: string, Job: string, Snapshot: [32]byte,
    Source: { Reference: string, Platform: string, Stage: int, Kind: string, Line: int },
    At: int64
  },
  Target: ImageResolveTarget,
  Index: uint64, Epoch: uint64
}
```

Target는 [현재 이미지 선택 타입](../../internal/cluster/control/image_resolve.go)의 Normalized/Kind/Source/Code·Owner/Trust와 optional Managed/External·ExternalReadSet이다. 서버는 전달된 Target를 권한으로 신뢰하지 않고 원 state에서 재계산해 비교한다. Builder는 실제 연결 member key와 같아야 하며 Target.Owner는 수신 owner여야 한다. queued·begin 없는 job·취소/철회된 job은 본문을 새로 읽지 못한다. 거부가 진행 중 원 source/Volume 참조를 반환하지는 않는다.

Root는 원 signed begin의 immutable FROM과 같아야 한다. Path는 root index에서 선택한 child digest들을 순서대로 담으며 최대8단계다. root와 같은 repository만 사용한다. 각 부모 descriptor의 digest/media/길이를 검증한 뒤에만 다음 child를 읽고, 선택한 manifest에 직접 속하는 config/layer만 연다. 임의 URL·foreign/embedded descriptor·중복 순환·다른 repository나 관계없는 blob은 거부한다. manifest/config1MiB·layer10GiB 및 기존 이미지 용량 경계를 유지한다.

응답 Info.Ref는 Path 끝의 manifest ref이며, 빈 Path면 Root다. kind2/4의 ready→data→최종 ok/EOF, 실제 전체 길이/지문·일정 메모리·원 body Close와 현재 권한 재검사는 일반 본문 읽기와 공유한다. ExpiresAt은 현재부터 최대900초이며 Nonce는 nonzero다. Basic/Bearer 자격은 원 owner의 기존 OCI client에서만 소비하고 본문 스트림에 포함하지 않는다. 내장 registry는 같은 원 Store/gate를 body Close까지 보유한다.

새 SDK 빌드는 이 본문을 원 source별 OCI session store에서 소비한다. [source policy 전환·임시 본문 수명](image-build-jobs/05-from-owner.md)을 따른다. 일반 CLI 사용자 읽기의 Query/Session 경계는 유지한다.

## 사용자 읽기·공통 종료

사용자 읽기는 기존 image-resolve의 현재 tenant 권한·repository trust·원 registry run/승인 source/read-set을 재사용한다. 내장 registry의 Ready heartbeat는 읽기 내용의 세대가 아니며 target에서 제외하지만, 실제 enabled/Ready/비 drain 상태와 원 owner/pin은 검사한다. 삭제된 좁은 외부 source를 익명 또는 넓은 자격으로 대체하지 않는다.

owner가 다른 노드이면 ingress가 원 Session·Body·사용자 proof를 유지하고 해당 owner의 fresh connection에 member Relay를 서명한다. 한 번만 전달하며 target 변경을 새 owner로 반복 우회하지 않는다. Unix는 kind3을 받지 않는다. kind4 응답은 Respond 주체만 보내고 UserAuth나 node key만으로 source 권한을 얻지 않는다. 실제 owner가 현재 quorum/사용자·source/read-set·원 run과 현재 peer admission을 전송 중과 마지막 결과 전에 검사한다.

헤더 파싱은30초, 초기 권한/계획은5초다. 인증 뒤 총 기한은 ExpiresAt/caller context 중 빠른 것, 각 I/O 유휴는60초다. 새 data를 내보내기 전에 최대8MiB 또는1초 간격으로 권한을 재확인한다. 노드별 handler2개·24KiB buffer와 transport backpressure로 제한하고 전체 blob을 메모리/관리 JSON/Raft에 모으지 않는다.

전용 Unix 연결은 전송 종료 뒤 재사용 cache에 남기지 않는다. 실제 native/HTTP body의 Close와 취소 뒤 원 Store gate/외부 reader hold를 반환한다. 내장 GC는 열린 content reader를 추월하지 않는다. EOF를 읽었다는 사실만으로 native reader join이나 Volume pin 반환을 주장하지 않는다.

## 내장 저장소의 대용량 HTTP

웹의 이미지 push·내장 layer GET은 기존 HTTPS OCI API를 계속 쓴다. `Specification.Blobs.BlobBytes`는 단일 blob/요청 한도, TotalBytes는 보존 전체 한도다. 10GiB push를 허용하려면 이 한도와 tenant Volume 여유를 명시해야 한다. manifest는 별도의 Metadata.ManifestBytes 한도를 쓴다. 큰 blob을 manifest/일반 User 응답 한도로 자르지 않는다.

HTTP 요청은 설정된 RequestTimeoutMS(100~300000ms)의 유한 시간 안에 끝나야 한다. PATCH 조각은 각각 그 한도·현재 자격을 따르고, 마지막 확정은 전체 digest를 검사한다. 기존 push lease·upload 복구·GC 경합 규칙을 유지한다. 크기 설정의 허용은 실제10GiB 저장/전송 성공의 증명이 아니며, 완료 근거는 RQ6 검증에서 구분한다.
