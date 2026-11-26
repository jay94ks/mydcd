## 계획과 수락

MVP에서 `WorkspaceBytes`는 컨텍스트 확장/빌드 입력 수락 예산이고 `CacheBytes`는 캐시 정리 목표다. 실제 파일시스템 쓰기 강제 상한이나 tenant별 디스크 고갈의 엄격한 격리는 보장하지 않는다. CPU·메모리·동시성·시간 제한과 원 작업/임시 자료 정리·실패/불명 정산은 유지하며, 디스크 부족을 다른 tenant 자료의 자동 삭제로 해결하지 않는다.

```sh
mydc --tenant tenant-a build run source --id build-one     # 최신 버전, 끝날 때까지 기다린다
mydc --tenant tenant-a build run source 3 --id build-two --no-wait
mydc --tenant tenant-a build show build-one
mydc --tenant tenant-a build list source
```

현재 tenant ManageRegistry·`begin-image-build` credential operation 권한이 필요하다.
선택 version·context·정책·설치 owner·등록 root/ACL·고정 builder 신뢰·결과 내장 registry와
진행 중인 이미지 회수 fence를 확인한다. 결과 registry의 초기 owner generation이 확보돼
있어야 한다. job ID와 삭제 이력은 재사용하지 않으며 tenant당 미종결 job은 최대128개다.

User purpose8 `image-build-job-plan` 요청은
`{Tenant,ImageBuildJob:{ID,Context,Version:[32]}}`다. 공통 Schema/Nonce/Session proof를
사용하며 `Reply.ImageBuildJobPlan`은 `{Schema:1,Spec,Change,RootRevision,Epoch,Index,Uses?}`다.
Spec은 `Schema,Cluster,Tenant,ID,Version,Number,Scope,Seal,Context,Policy,ContextRevision,PolicyRevision,RegistryAuthority,RegistryGeneration,RegistrySpec,Commit?,CreatedAt`이다.
컨텍스트의 공개 ARG와 Vault 참조는 포함하되 Secret·Git/Docker 자격의 값은 포함하지 않는다.
Spec metadata는24KiB 이내다. version의 원 Dockerfile 경로를 사용하며 현재 context의
인자·태그·platform과 정책/registry generation을 고정한다. 보존 version의 원 expanded 한도와 별도로 현재 정책의 WorkspaceBytes 이하인지도 검사한다. 과거 version을 보존한다는 이유로 새 빌드의 입력 예산을 우회하지 않는다. `{commit}` 태그는 고정 Git
commit이 있는 version에서만 사용할 수 있고 ZIP version에서 빈 값으로 대체하지 않는다. Git version의 원 게시 증거와 일치하는 Commit을 Spec에 고정하며 현재 repository ref나 최신 commit으로 바꾸지 않는다.

`Change`는 `{Tenant,ID,Context,Version:[32],Snapshot:[32],At}`다. Snapshot은
`mydc-imagebuild-job-1\x00`와 Spec의 canonical Go JSON을 SHA-256한 값이다.
UserOperation action `begin-image-build`, Expected0으로 제출한다. 수락 시 같은 현재
상태에서 Spec을 재구성해 Snapshot과 대조하며 plan At부터120초 이내여야 한다.
원 operation은 기존 `control/image-builds` root CAS와 사용자 서명/관리 승인을 사용한다.
job과 version 사용 참조는 같은 FSM 변경으로 확정한다.

CLI는 같은 `--id`의 원 journal이 있으면 새 plan부터 만들지 않는다. 저장된 payload/Expected/epoch로
result를 조회하고, 없으면 같은 원 operation을 다시 보낸다(`mydc op resume ID`도 같다). 새로운 job ID나 사용자
operation ID로 불명 결과를 자동 대체하지 않는다.

