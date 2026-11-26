## User 조회 메시지

등록된 Git source의 확인은 `build context check CONTEXT` 또는 User `check-build-context {Tenant,ImageBuildSource:{ID}}`다. 현재 ManageRegistry·허용 node/root/context/policy에 고정하고 owner가 설치된 정확한 tenant/profile/repository 자격으로 fetch한다. mutable ref를 단일 commit으로 고정한 뒤 지정 폴더의 Dockerfile과 모든 target platform의 FROM/COPY/RUN 외부 이미지 신뢰를 검사한다. `#syntax`/BUILDKIT_SYNTAX override·symlink/submodule/LFS pointer와 추가 source fetch는 받지 않는다.

Reply의 `ImageBuildSource`는 `{Schema:1,Context,Code,Commit,Tree:[32],Entries,BaseSources,ExpandedBytes,ContextRevision,PolicyRevision,Epoch}`다. Code는 `OK|SOURCE_FETCH|UNTRUSTED_BASE|INVALID_CONTEXT`; 실패에는 commit/tree/개수·본문/자격을 넣지 않는다. 현재 repository 전송은64MiB pack/HTTP·expanded object128MiB·16,384 objects·최대300초이며 workspace와 ZIP 한도도 적용한다. 이는 실제 go-git 읽기·구조/trust 확인이며 private FROM의 실제 pull·BuildKit build/push나 Git version 보관/자동 build를 수행하지 않는다. 원 source/정책/사용자 권한이 바뀌면 확인 결과를 현재 결과로 반환하지 않는다.

Unix와 QUIC 모두 기존 User purpose8 kind1/2로 같은 메시지를 사용한다. 연결·Session proof는 [Unix API](../unix-sockets.md)와 [MYDCP](../../protocol/mydcp.md)를 따른다.

```json
{"Schema":1,"Method":"image-builds","UserKey":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Tenant":"tenant-a","Nonce":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"ImageBuild":{"Part":"contexts","ID":"","Upload":""}}
```

| `ImageBuild.Part` | selector | 결과 |
|---|---|---|
| `caches` | ID=context 선택, Node=node 선택; Upload/Job 빈 값 | Caches: 원 namespace별 node 요약·상태. [필드·cursor](../image-build-jobs/12-section.md) |
| `policy` | ID/Upload 빈 값 | Policies: `{Spec,Revision,Deleted}` |
| `contexts` | ID 선택 | Contexts: `{Spec,Revision,NextVersion,Deleted,DataGeneration?,GitObservation?}`. DataGeneration은 편집 데이터 수명이며 설정 revision과 구분 |
| `versions` | ID=context 필수 | Versions: `{ID:[32],Context,Upload,Number,Bytes,ExpandedBytes,Entries,Tree:[32],At,Deleted,Commit?}` |
| `uploads` | Upload 선택 | 원 creator의 Uploads: `{Scope,Revision,Received,Closed,Version:[32]}` |
| `missing` | Upload 필수 | 최대256개 `Missing` index와 `UploadRevision`. 닫힌/만료 upload는 conflict |

성공 Reply의 `ImageBuild`는 `{Schema:1,Tenant,Part,RootRevision,Epoch,Policies?,Contexts?,Uploads?,Versions?,Missing?,UploadRevision?,Next?}`다. cache part는 별도 Caches/InventoryRoot와 최대4행·24KiB의 [요약 목록](../image-build-jobs/12-section.md)을 사용한다. Node selector는 caches에서만 받는다. 정책/컨텍스트/버전/업로드는 최대8개·공개 row 합계96KiB 이내다. 원 Session·UserOperation·원 서명은 공개 페이지에 넣지 않는다. Snapshot cursor는 cluster/tenant/selector/root revision/epoch에 고정하고 `After`로 이어 간다. 그 사이 상태가 바뀌면 conflict이며 새 조회부터 시작한다. 부분 페이지를 전체 결과로 판단하지 않는다.

```sh
mydc --tenant tenant-a build policy show
mydc --tenant tenant-a build context list
mydc --tenant tenant-a build context versions source
```

