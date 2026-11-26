# MyDC 문서

MyDC는 특정 tenant의 앱/서비스를 `app.yaml`로 배포하고 관리하는 MVP 엔진이다. 클러스터 관리 자원은 관리 명령(`tenant`·`network`·`route`, `manage apply`)으로 구성한다.

이 디렉터리는 **사용 설명서·API/입력 명세·주요 알고리즘·메커니즘 설명**을 담는다. 개발 계획·검토/변경 기록·시험 절차·검증 결과는 루트 devel/에 둔다.

## 처음 사용하는 경우

이미지 빌드의 tenant 정책·컨텍스트·원 ZIP upload metadata와 공개 조회는 [빌드 컨텍스트 API](reference/image-build-contexts.md)를 따른다. 관리 수락과 실제 builder/owner I/O 연결 범위는 구분한다.

tenant manager가 Volume·빌드 정책에 사용할 노드 저장 root를 선택하는 방법은 [tenant 저장 경로 조회](reference/tenant-storage.md)를 따른다. 시스템 전용 전체 저장 경로 조회와 구분한다.

- [이미지 빌드 job](reference/image-build-jobs.md): 고정 입력·원 operation·상태/취소/기록 삭제·owner 정산·가린 로그/cursor·빌드 캐시 관측·노드/컨텍스트별 목록

1. [Quick-start](quick.md)로 단일/3노드 클러스터 구축과 실행 중 노드 추가·제거를 진행한다. [사용 설명서](guides/README.md)에서 전체 사용 순서를 확인한다.
2. [mydc 명령](cli/README.md)(새 체계, 옮기는 중)과 [CLI·설정](configuration/cli.md)으로 cluster 등록·login·tenant 선택과 배포 명령을 확인한다.
3. [app.yaml과 tenant 설정](architecture/app-and-cluster-spec.md)의 책임을 구분하고 [샘플 앱](examples/README.md)을 읽는다.
4. 로컬 API를 연결하려면 [Unix 소켓 끝점과 프로토콜](reference/unix-sockets.md)을 읽는다.
5. 실행 중 앱의 로그·프로세스·리소스 조회와 interactive 실행은 [컨테이너 운영](reference/container-operations.md)을 따른다.
6. 노드·tenant·앱으로 Task를 찾는 조회는 [Task 관측](reference/task-observability.md)을 따른다.
7. 배포 원문을 조회해 수정하거나 이전 입력을 찾으려면 [app.yaml 원문·버전](reference/app-source.md)을 읽는다.
8. 서버 자원·Mesh 연결·합의 상태를 조회하려면 [노드 관측](reference/node-observations.md)을 읽는다.
9. 컨테이너에 비밀값을 파일/환경 변수로 공급하려면 [Secret 공급](reference/secret-delivery.md)을 읽는다.
10. 원 Task만 재시작하거나 노드의 새 배치를 제어하려면 [운영 조치](reference/task-actions.md)를 읽는다.
11. 배포 전 입력 검사를 연결하려면 [CD 후보 승인·반려](reference/cd-candidate-decisions.md)를 읽는다.
12. 합의 snapshot·로그를 수동 회수하려면 [Raft 유지보수](reference/raft-maintenance.md)를 읽는다.
13. 내장 이미지 저장소를 정지/시작하려면 [Registry 조치](reference/registry-actions.md)를 읽는다.
14. 끊긴 서버 간 연결을 복구하려면 [Tunnel reconnect](reference/tunnel-reconnect.md)를 읽는다.
15. 미사용 컨테이너 이미지를 회수하려면 [노드 캐시 정리](reference/node-image-cache.md)를 읽는다.
16. 짧은 재시작·실패·CD 전이를 이어 읽으려면 [관측 이벤트](reference/events.md)를 읽는다.
17. 외부 저장소의 자격 참조를 관리하려면 [외부 registry 정의](reference/external-registries.md)를 읽는다. 실제 private pull 연결 범위도 함께 확인한다.
18. tag/digest와 현재 신뢰를 확인하려면 [이미지 참조 확인](reference/image-resolution.md)을 읽는다.
19. 이미지와 외부 source를 참조하는 앱을 확인하려면 [이미지 사용처](reference/image-usages.md)를 읽는다.

20. 저장소의 repository·태그·digest와 용량을 읽으려면 [이미지 목록](reference/registry-images.md), 명시 정리와 원 결과는 [삭제·GC](reference/registry-maintenance.md)를 읽는다.
21. 노드의 전용 OS 계정에 대화형으로 접속하려면 [노드 shell](reference/node-shell.md)의 사용자/노드 grant·준비·sudo·원 세션 수명을 읽는다.

서비스 내부 POST와 Git source 연결 검사는 [서비스·Git 진단](reference/service-diagnostics.md)을 따른다.

## 문서 분류

| 분류 | 읽을 내용 |
|---|---|
| [사용 설명서](guides/README.md) | 실행·접속·로그인·배포 순서와 설정 |
| [API·입력 명세](reference/README.md) | Unix 끝점, MYDCP, 명령 대상, app/cluster 입력, 자원 소유권 |
| [아키텍처](architecture/README.md) | 모듈과 상태·통신·관리/선언의 경계 |
| [주요 알고리즘](algorithms/README.md) | Raft 확정, 원 요청/CAS, reconcile, 참조와 종료 |
| [메커니즘](mechanisms/README.md) | cluster/tenant·망·앱/lifecycle·Secret/Volume·CD의 동작 |
| [예제](examples/README.md) | CLI 프로필, PHP/MySQL 샘플 앱, registry, 교차 tenant 경로 |

## 관리 기준

문서의 지원 범위는 실제 구현을 기준으로 쓴다. 계획이나 과거 시험의 한계를 현재 제품의 지원 여부로 대신하지 않는다. 실행 이력·완료 근거는 HISTORY, 남은 작업은 Milestones, 원 검증 자료는 검증 기록에서 확인한다.

`development/`, `testing/`, `proposals/`는 과거 기록과 시험 코드의 참조를 보존하는 호환 심볼릭 링크다. 실제 파일은 `devel/`에 있으며 새 문서는 정식 경로를 사용한다.

사용자·tenant 관리 화면의 조회 API는 [사용자·구성원 조회](reference/user-catalog.md)를 따른다.

장수 client의 다중 사용자·pin·새 연결 Session 재사용과 본인 키 변경은 [client 인증](reference/client-authentication.md)을 따른다.

컨테이너의 실제 설정·목표와의 차이·최근 서비스 검사는 [컨테이너 실제 설정 조회](reference/container-detail.md)를 따른다.

- [새 사용자의 최초 로그인 수단](reference/initial-credentials.md): 시스템 관리자 발급과 보호 저장·원 작업 복구.

이미지 manifest·config/history·외부 layer blob은 [이미지 내용 전송](reference/image-content.md)의 고정 digest·원 사용자 권한·스트림/EOF 계약으로 읽는다.

Ingress 매핑·최근 지표·Raft 차단은 [Ingress 운영](reference/ingress-management.md), 인증서 보호 입력과 동적 공급은 [클러스터 인증서 보관함](reference/certificate-store.md)을 따른다.

공유 external/local listener·동적 SNI·route별 분배는 [Ingress 게이트웨이](reference/ingress-gateways.md)를 따른다.

- [단독 컨테이너](reference/standalone.md)
- [Volume 파일 작업](reference/volume-files.md)

공유 자원의 참조·삭제 차단 사용처·백업 한도·서명 망 종료와 DNS·로그인 전 데몬 판은 [관리 자원 조회](reference/resource-queries.md)를 따른다.

Lifecycle 원본을 검사·업로드하고 정확한 과거 버전을 읽으려면 [원본 API](reference/lifecycle-sources.md)를 따른다.
