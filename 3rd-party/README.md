# 고정 외부 소스

`nftables`는 기존 검증된 Go module cache의 `v0.3.0` 소스를 보존한 local fork다.
원 LICENSE/저작권과 파일별 원본·수정 SHA-256은 [pin](nftables.pin.json)에,
유일한 제품 수정은 [patch](nftables.patch)에 둔다. conntrack setter의
`NFTA_CT_SREG`를 디코딩하여 원 register/SourceRegister를 읽기 대조할 수 있게 한다.
읽기 필드를 무시하거나 버전·전이 의존성을 최신화하지 않는다. root go.mod의
명시 replace를 사용하며 일반 build/test에서 다운로드·복사·patch를 자동 수행하지 않는다.
이 소스 준비 자체는 실제 kernel 규칙 검증 완료가 아니다.

`raft`는 기존 검증된 Go module cache의 hashicorp/raft `v1.8.0` 소스를 보존한
local fork다. 원 LICENSE/저작권과 파일별 원본·수정 SHA-256은 [pin](raft.pin.json)에,
유일한 제품 수정은 [patch](raft.patch)에 둔다. follower가 AppendEntries 응답에
자신의 commit index를 싣고, leader는 commit index가 오를 때 복제를 즉시 깨우며
follower에게 필요 없는 빈 AppendEntries를 보내지 않는다. heartbeat 간격을
`HeartbeatInterval`로 따로 정할 수 있고(0이면 upstream과 같은 HeartbeatTimeout/10),
그때 알려진 leader가 없는 follower는 ElectionTimeout만 기다린다. transport가
`PeerConnectionLost`로 연결 상실을 알리면 follower는 곧 선거를 시작하고 leader는
lease를 바로 다시 확인한다. `PeerConnected`로 연결이 다시 생기면 leader는 그 follower에게 바로 heartbeat를 보낸다(재시작한 follower가 HeartbeatInterval을 기다리지 않고 leader를 안다). term·투표·lease 규칙과 로그 일치 규칙은 바꾸지 않는다.
root go.mod의 명시 replace를 사용한다.

`go-containerregistry`는 upstream `v0.22.1`, commit
`8a72a424fdecb4caa14f2d525e5d2503331442b5`의 submodule이다.
MyDC가 사용하는 manifest/tag와 upload 저장 훅의 최소 수정은
[patch](go-containerregistry.patch)와 [고정 정보](go-containerregistry.pin.json)에 보존한다.
원 LICENSE·기존 저작권 표시는 checkout 안에 유지한다.

공개 소스 트리(jay94ks/mydcd)에는 수정을 적용한 `go-containerregistry` 트리가 submodule 대신 그대로 들어 있어 이 준비 단계가 없다. 개발 리포의 깨끗한 신규 checkout의 명시 준비 절차는 다음과 같다. 이미 수정이 적용된
작업 디렉터리에서 다시 적용하지 않는다. 원 commit과 수정 파일 hash는 pin에
기록한 값과 대조한다.

```sh
git submodule update --init -- 3rd-party/go-containerregistry
git -C 3rd-party/go-containerregistry rev-parse HEAD
git -C 3rd-party/go-containerregistry apply --check ../go-containerregistry.patch
git -C 3rd-party/go-containerregistry apply ../go-containerregistry.patch
```

root `go.mod`는 이 checkout을 명시 replace한다. 일반 빌드/검증은
offline·readonly/cache를 사용하고 clone/update/patch 적용·toolchain 다운로드를
자동 수행하지 않는다. 새 의존성 확보는 별도 명시 단계다.

수정은 upstream OCI handler의 저장·upload streaming 훅으로 한정한다.
인증·tenant 선택·현재 권한·TLS·Volume writer·서버 종료 정산은 MyDC의 책임이다.
upstream의 기본 메모리 저장을 제품 내구 저장으로 사용하지 않는다.
E5 구현/검증 순서는 [마일스톤](../MILESTONES.md)을 따른다.
