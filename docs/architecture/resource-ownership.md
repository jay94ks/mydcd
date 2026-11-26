# 클러스터 관리 자원과 앱/서비스 정의 자원

이 표는 자원의 정의·변경·삭제 권한과 수명의 기준이다. 클러스터가 관리하는 자원도 대부분 특정 tenant에 속하며, 클러스터 전역에서 모든 tenant가 공유한다는 뜻은 아니다. 앱이 정의하는 자원의 실제 생성·관측·종료도 daemon이 수행하지만, 그 목표와 소유 inventory는 해당 앱에 속한다.

입력 형식은 [app.yaml·cluster.yaml 명세](app-and-cluster-spec.md), 명령과 작업 실행은 [관리 명령과 앱 선언](commands-and-declarations.md)과 [명령어 적용대상표](command-targets.md)를 따른다. 아래 표는 설계 기준이며 개별 관리 action이나 native 연결의 구현 완료를 뜻하지 않는다. 실제 지원 입력은 입력 명세와 CLI 문서에 명시한 범위로 제한한다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| 자원 분류표 | [resource-ownership/01-section.md](resource-ownership/01-section.md) |
| 이름 참조와 수명 | [resource-ownership/02-section.md](resource-ownership/02-section.md) |
| 유지·관리 규칙 | [resource-ownership/03-section.md](resource-ownership/03-section.md) |
| 사용자 컨테이너 운영 조회의 소유권 | [resource-ownership/04-section.md](resource-ownership/04-section.md) |
| 서비스 진단의 trust와 임시 참조 | [resource-ownership/05-trust.md](resource-ownership/05-trust.md) |
| Tenant 단독 컨테이너와 파일 위임 | [resource-ownership/06-tenant.md](resource-ownership/06-tenant.md) |
| 자원·삭제 차단 공개 projection | [resource-ownership/07-projection.md](resource-ownership/07-projection.md) |
| Lifecycle editor 원본·임시 입력 | [resource-ownership/08-lifecycle-editor.md](resource-ownership/08-lifecycle-editor.md) |
