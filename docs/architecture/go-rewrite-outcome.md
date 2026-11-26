# Go 재작성 결과 보고서

보고 기준: **2026-11-21**. Go 재작성의 실제 채택 구성·구현 결과와 보존된 검증 근거를 정리한다. 제품은 **MVP**이며, 현재 실행 방법은 [Quick-start](../quick.md), 상세 경계는 [모듈 설계](modules.md)·[MYDCP](../protocol/mydcp.md)를 따른다.

## 결과

C/C++ 중심 구현에서 Go의 `mydc`·`mydcd`와 공용 내부 패키지로 전환했다. 합의·복제·복구는 HashiCorp Raft의 로그/Snapshot을 기준으로 통합하고, FSM과 노드 운영 저장에는 bbolt를 채택했다. 별도 해시체인·Delta 동기화 계층과 C++ 공유 라이브러리 ABI는 활성 제품에 사용하지 않는다.

Go 재작성 R0–R5의 **29/29개 항목**은 R5 완료 근거로 마감했다. 이후 앱·tenant·Vault/Volume·CD·CLI 기능을 결합한 독립 Linux KVM 게스트2개 최종 검증은 E8 완료 근거에 기록되어 있다. 현재 MILESTONES.md에는 등록된 미완료 마일스톤이 없다.

과거 검토의 라이브러리 후보·예상 공수·적합성 확인 계획은 실제 결과와 구분한다. 당시 일정 추정으로 실제 개발 인주·비용 절감률·성능 향상 배수를 산출하지 않는다. 상세 작업/변경 이력은 HISTORY에 보관한다.

## 실제 채택한 구성

고정 버전과 local 수정의 기준은 [go.mod](../../go.mod)·[go.sum](../../go.sum)·실제 런타임 구성이다. 아래는 후보 목록이 아니라 현재 사용하는 책임 배치다.

| 경계 | 채택한 구성 | 결과 |
|---|---|---|
| 실행 파일 | Go `cmd/mydc`, `cmd/mydcd` | CLI는 명령 파싱/자격·원 작업 관리를, daemon은 클러스터와 실제 노드 효과를 담당 |
| 합의 | HashiCorp Raft | 선거·로그 복제·구성 변경·Snapshot을 라이브러리에 위임. 자체 Raft 구현 없음 |
| Raft log/stable | raft-boltdb/v2 | Raft 전용 저장 파일. FSM/운영 DB와의 원자성을 가정하지 않고 재생으로 연결 |
| FSM·운영 저장 | bbolt | 공유 상태·원 결과·적용 위치의 원자 저장과 노드별 운영 원본 분리. Pebble/RocksDB는 현재 선택이 아님 |
| 노드 간 MYDCP | quic-go + Go TLS/Ed25519 + 자체 frame/TLV | 인증된 QUIC/UDP 안에 관리·Raft·Snapshot·상태 보고·터널 경계 수용 |
| 로컬 관리 | AF_UNIX + TLS + MYDCP record | 기본 `/var/run/mydc.sock`. 네트워크와 동일한 User/SecretInput 코어 사용 |
| HTTP Ingress | net/http·httputil·x/net/http2·quic-go/http3 | 외부 HTTP/1.1·2·3 처리. MYDCP 관리 신뢰 경계와 분리 |
| Docker 실행 | Moby Docker SDK | 컨테이너·network/IPAM·exec·시작/종료/조회는 SDK 활용 |
| Linux 망 | netlink/netns·nftables·작은 TUN 어댑터 | CIDR/주소 권위와 실제 장치·경로·방화벽·패킷 효과 분리 |
| 입력 | yaml.v3·compose-go | app.yaml 파싱과 MyDC 정책 검증. tenant 관리 변경은 별도 관리 명령 |
| Secret·인증 | Vault API·Argon2id·Go crypto·보호 TTY | 비밀 입력/공급자와 공개 승인 metadata 분리. wallet은 Argon2id 키 유도와 저장마다 무작위 nonce 사용 |
| 내장 DNS | miekg/dns | CIDR/IPAM 통제 및 이름 서비스. DHCP 서버는 구현 범위에서 제외 |
| 내장 CD | go-git + 기존 앱 계획/실행 코어 | 고정 Git 입력과 원 operation을 연결. MyDC에 필요한 동작만 자체 정의 |
| tenant registry | go-containerregistry + 고정 저장 수정 | mydcd가 직접 OCI registry 서비스. 별도 registry 컨테이너 없음 |
| lifecycle 사용자 검사 | Yaegi·선택 compiled Go CLI | 접속 기반 생존 검사·결과별 부가 동작. 실제 컨테이너 제어는 daemon의 Docker SDK 경계 |

HashiCorp Raft 대신 etcd Raft를 쓰는 안, Pebble 또는 RocksDB/CGO를 쓰는 안, 별도 TCP Raft listener를 여는 안은 현재 구성에 포함되지 않는다. 일반 MYDCP의 네트워크 전송은 QUIC/UDP이며 TCP listener를 제공한다는 의미가 아니다.

## 합의·저장·부작용의 책임

확정 흐름은 다음과 같다.

```text
CLI/관리 API → 현재 인증·권한·원 요청/서명·CAS
            → Raft 과반수 확정
            → 결정적 FSM의 상태·요청 결과·적용 위치 원자 저장
            → 노드별 원 journal과 실제 Docker/Network/Ingress 효과
            → 관측·원 결과 정산·참조 반환
```

- 공유 관리 상태의 순서·확정·복구는 하나의 Raft 로그/Snapshot 경계를 따른다. 별도 체인 head/parent·Delta 전송·독립 분기 병합 경로를 두지 않는다.
- SHA-256과 서명은 내용 무결성·신원·정확한 원 입력 결합에 사용한다. 해시를 쓴다는 사실이 별도 해시체인 동기화를 뜻하지 않는다.
- 공유 FSM/원 결과와 node-local 운영 journal·실제 Volume 데이터·비밀키의 소유권을 구분한다. 승인된 non-voter도 같은 관리 FSM을 받지만 정족수는 voter만 계산한다.
- FSM 재생은 외부 효과 재실행 명령이 아니다. 단절/timeout 뒤에는 원 ID·대상·불명 상태를 보존하고 실제 결과를 확인하여 정산한다.
- N1/Q1은 명시된 단일 노드 구성이다. 다중 노드가 단절되었다고 voter 수를 임의로 줄이거나 standalone으로 전환하지 않는다.

상세 알고리즘은 [합의·원 요청](../algorithms/consensus-and-requests.md)과 [재조정·정산](../algorithms/reconciliation.md)에 기술한다.

## 구현한 사용자 경로

| 영역 | 현재 결과 | 제품 설명 |
|---|---|---|
| 초기 설치·node 운영 | 빈 managed init·명시 관리자 등록·non-voter 가입/승격·실행 중 격리/복귀/제거 | [Quick-start](../quick.md), [cluster](../mechanisms/cluster.md) |
| CLI·다중 사용자 | Linux user별 wallet·여러 cluster/tenant 프로필·계정별 login·명시 사용자 선택·Unix/원격 관리·원 작업 조회/재개 | [CLI 신원](../mechanisms/cli-identity.md), [명령 대상](command-targets.md) |
| 앱 배포 | tenant의 이름 있는 app.yaml 계획·배포·노드 배치·이름 기반 관리 자원 참조·종료/보존 | [입력 명세](app-and-cluster-spec.md), [앱/lifecycle](../mechanisms/workloads.md) |
| 망·Ingress | 전역 CIDR 유일성·Docker IPAM·MYDCP TUN·DNS·양측 승인 cross-tenant route·HTTP/1.1/2/3 | [네트워크](../mechanisms/networking.md) |
| Secret·Volume | 계층 Group/Secret·순서 기반 키 병합·서명 승인·보호 값 입력·이관/backup/restore·node-fixed Volume·추가 저장 root | [Secret/Volume](../mechanisms/secrets-and-volumes.md), [자원표](resource-ownership.md) |
| CD·registry | 원 Git/앱 실행·target CAS·명시 strict CAS·장애 재개·tenant registry와 신뢰 출처 정책 | [delivery](../mechanisms/delivery.md) |
| lifecycle | 내장 Docker 호환 검사·사용자 Yaegi/compiled 검사·job 기반 compiler·tenant source/compiled cache 정산 | [앱/lifecycle](../mechanisms/workloads.md) |

PHP/MySQL은 범용 엔진의 샘플 app.yaml이다. 제품이 해당 이미지·이름·포트·SQL 로직에 최적화되었다는 의미가 아니다.

## 검증 결과와 해석 범위

여기서는 보존된 완료 근거를 인용한다. 문서 개정을 위해 빌드·제품·커널/Docker/KVM 시험을 다시 실행하지 않았다.

| 근거 | 입증한 경계 | 범위 |
|---|---|---|
| R5 완료 | 실제 인증 CLI/MYDCP/Raft/DB·N3/Q2와 N4/Q3·non-voter·리더/분할·동일 DB/Snapshot·실제 Engine/TUN/Ingress·race/fuzz·유한 부하 | 로컬 한 호스트에서 독립 프로세스/Engine/namespace 기반 Go 재작성 검증 |
| E8 완료 | D1.07·D2.10·D3.10·D4.08·D5.12·D6.07·D7.07의 실제 기능 결합 | 같은 물리 WSL 호스트의 독립 Linux KVM 게스트2개 |
| E8 공개 수락 근거 | 원 앱·데이터·CD·자격/tenant·실제 owner 정산과 최종 종료의 공개 증거 | 원 입력·환경·operation과 기록된 실행 범위에 한정 |
| E8 원상 복구/정리 | 완료 뒤 소유 임시 디스크/DB·자식 정리 및 호스트 확인 | 원 증거와 현재 Go/module/test cache 보존 |

E8에서는 앱 통신·DNS/Ingress·SQL/재기동, Vault/Group·cold move/backup/restore, 네트워크 disable/drain·양 owner closure, CD/CAS·재개, tenant/registry·노드 lifecycle, Yaegi/compiled 검사와 물리 cache 회수, Unix/원격·다중 프로필/계정을 확인했다. 완료 기준과 한계의 원문은 위 JSON 및 HISTORY의 E8 완료를 따른다.

다음은 이 결과로 주장하지 않는다.

- 서로 다른 물리 호스트의 장애 독립성.
- N2/Q2에서1대 단절 후 남은1대의 무정족수 관리 변경.
- 모든 앱·스토리지·네트워크 환경의 호환성이나 생산 운영 규모의 성능/SLA.
- C++ DB/wire/ABI와의 호환 또는 기존 운영 데이터 자동 이전.
- UI·ACME/Certbot·일반 TCP/UDP 포트 노출 및 미승인 고도화의 구현 완료.

## 전환 효과와 남은 개선 검토

활성 제품은 C++의 Folly/Fizz/mvfst/Proxygen·RocksDB 조합 대신 Go 패키지와 채택 SDK를 연결한다. 이로써 해당 C++ 제품 의존성의 수동 빌드/ABI 조합을 활성 제품 경로에서 제외했다. 다만 Linux 커널·Docker·인증·내구 저장·네트워크 장애·자원 정산 책임은 언어 변경 뒤에도 실제 어댑터에서 검증해야 한다.

초기 알고리즘은 재사용 가능한 제품 코어로 검증하고 같은 코어를 실제 연동에 사용했다. 후속 구현 중 발견된 계약 결함은 영향 범위를 수정하여 재검증하며, 주요 시험은 해당 마일스톤의 구현 묶음 끝에서 수행하는 Workflow를 적용한다. Go의 GC나 테스트 cache는 실제 외부 자원의 종료/정산 증명이 아니다.

완료 후의 진단·도움말·문서·검증 중복 정리 및 Unix 연결 재사용 후보는 별도 현재 구현 개선 검토에 둔다. 이 결과 보고서의 완료 근거와 새로운 개선 후보를 혼합하지 않는다.
