## 조회·취소·기록 삭제

User `image-builds {Tenant,ImageBuild:{Part:"jobs",ID?:context,Job?:job},After?}`를 사용한다.
현재 Read 또는 ManageRegistry의 같은 snapshot 페이지이며 `Reply.ImageBuild.Jobs`는 최대8개다.
각 행은 `{ID,Context,Node,User,Phase,Version:[32],Number,Revision,CreatedAt,ClosedAt,Cancel,Deleted,Result?}`다.
Result는 `{Code,Image,Bytes}`이며 phase와 별도로 가짜 결과를 만들지 않는다. 원 Session·서명·Secret 값은
공개하지 않는다. 관련 namespace가 바뀌면 metadata cursor는 conflict다.

```sh
mydc --tenant tenant-a build cancel build-one
mydc --tenant tenant-a build delete build-one
```

`cancel-image-build {Tenant,ID}`는 해당 job Revision CAS로 Cancel을 기록한다.
`queued/running/unknown` 어디서든 취소를 요청할 수 있지만 native 정리가 확인되기 전에는
종결하지 않는다. `delete-image-build-job {Tenant,ID}`도 같은 Revision CAS이며 owner closure가
있는 종결 기록만 tombstone으로 바꾼다. 관리자 정리 권한과 원 데이터 보존 계약을 유지한다.

기본 전이는 `queued → running → succeeded|failed|cancelled`다. 실행 결과가 불명확하면
`running → unknown`으로 두고 원 실행만 관측·정산한다. unknown에서 새 실행으로 되돌아가지 않는다.
기동 전의 실패·취소도 owner가 미기동/정리 근거를 확인한 closure로 종결한다. 성공 closure는
queued에서 수락하지 않으며 `OK` 결과는 원 출력 repository의 SHA-256 digest와 양의 크기를
가리켜야 한다. 원 효과가 먼저 완료된 경우 취소 요청 이후에도 그 성공을 정산할 수 있다.

종결되지 않은 job은 builder·고정 FROM·출력 태그를 공통 이미지 사용 참조로 보호한다.
성공한 미삭제 기록은 결과 digest도 보호한다. **모든 미삭제 빌드 기록**은 원 version을
보호하므로 기록을 명시 삭제하기 전에는 version을 삭제/회수할 수 없다. node/root 제거와
관리 epoch 회전은 미종결 job을 누락하지 않으며 tenant 전체 종료도 기록/자료 정산을 요구한다.

