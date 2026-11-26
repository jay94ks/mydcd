# mydc-web HTTP API (`/api/v1`)

> 상태: **구현 중 (W1.2)**. 데몬은 `cmd/mydc-web`, 서버 코드는 `internal/web/server`, 자체 데이터는 `internal/web/store`(bbolt)다. mydcd와는 [client 인터페이스](../../internal/web/mydc/client.go)로만 이야기하며, method마다 real/mock 상태는 [상태표](../../apps/mydc-web/CLUSTER_METHODS.md)를 따른다. mock 상태 method에 기대는 끝점은 가짜 어댑터에서만 동작한다. 화면·데이터 원칙은 web-ui-plan.

웹 앱은 자기 관리 권한이 없다. 모든 조회·변경은 로그인한 사용자 자신의 MYDCP 세션으로 실행되고, 권한 판단은 매번 mydcd가 한다.

## 절 목록

이 문서는 절마다 파일로 나뉘어 있다.

| 절 | 파일 |
|---|---|
| mydcd와 mydc-web의 책임 경계 | [web-api/01-mydcd-mydc-web.md](web-api/01-mydcd-mydc-web.md) |
| 공통 규칙 | [web-api/02-section.md](web-api/02-section.md) |
| 로그인 | [web-api/03-section.md](web-api/03-section.md) |
| 작업(operation) | [web-api/04-operation.md](web-api/04-operation.md) |
| 조회 | [web-api/05-section.md](web-api/05-section.md) |
| 배포 (app.yaml 업로드 → up) | [web-api/06-app-yaml-up.md](web-api/06-app-yaml-up.md) |
| 이미지 신뢰 출처 | [web-api/07-ui-82-req-45.md](web-api/07-ui-82-req-45.md) |
| 내장 저장소 (UI-80) | [web-api/08-ui-80.md](web-api/08-ui-80.md) |
| 외부 이미지 저장소 로그인 (mydcd 실제 계약, REQ-17) | [web-api/09-mydcd-req-17.md](web-api/09-mydcd-req-17.md) |
| 이미지 빌드 (mydcd 실제 계약) | [web-api/10-mydcd.md](web-api/10-mydcd.md) |
| 자동 배포 (UI-40~43) | [web-api/11-ui-40-43.md](web-api/11-ui-40-43.md) |
| 클러스터 내부 웹훅 호출 | [web-api/12-req-24-mock.md](web-api/12-req-24-mock.md) |
| 장애 대응 (REQ-9·11 mock) | [web-api/13-req-9-11-mock.md](web-api/13-req-9-11-mock.md) |
| 컨테이너 상세·이력·로그와 옮기기 전 검사 | [web-api/14-req-20-mock-req-7-mock.md](web-api/14-req-20-mock-req-7-mock.md) |
| 컨테이너 스트림 (purpose15) | [web-api/15-purpose15.md](web-api/15-purpose15.md) |
| 앱 내리기와 보관된 앱 (웹 bbolt) | [web-api/16-bbolt.md](web-api/16-bbolt.md) |
| 화면 보조 자료 (웹 bbolt) | [web-api/17-bbolt.md](web-api/17-bbolt.md) |
| 봉인 파일 상태 | [web-api/18-section.md](web-api/18-section.md) |
| 웹 앱 설정 (UI-C1, 시스템 관리자) | [web-api/19-ui-c1.md](web-api/19-ui-c1.md) |
| 설정 변경 기록 (UI-A3) | [web-api/20-ui-a3.md](web-api/20-ui-a3.md) |
| 알림 (UI-C0) | [web-api/21-ui-c0.md](web-api/21-ui-c0.md) |
| 외부 DNS (UI-54~56) | [web-api/22-dns-ui-54-56.md](web-api/22-dns-ui-54-56.md) |
| 인증서 자동화 (UI-57~59, 시스템 관리자) | [web-api/23-ui-57-59.md](web-api/23-ui-57-59.md) |
| 공유 자원 만들기 (UI-50·60·61, 비밀값 보관함) | [web-api/24-ui-50-60-61.md](web-api/24-ui-50-60-61.md) |
| 서버 추가 (UI-13, 시스템 관리자) | [web-api/25-ui-13.md](web-api/25-ui-13.md) |
| 서버 셸 | [web-api/26-ui-1a-req-67-mock.md](web-api/26-ui-1a-req-67-mock.md) |
| 서버 저장 경로와 작업 공간 서버 한도 (UI-14·16, 시스템 관리자) | [web-api/27-ui-14-16.md](web-api/27-ui-14-16.md) |
| 원장 교체 (rotate-ledger, 시스템 관리자) | [web-api/28-rotate-ledger.md](web-api/28-rotate-ledger.md) |
| 작업 공간 종료 (UI-22, 시스템 관리자) | [web-api/29-ui-22.md](web-api/29-ui-22.md) |
| 작업 공간 간 연결 (UI-53) | [web-api/30-ui-53.md](web-api/30-ui-53.md) |
| 망 변경·폐기 (UI-50·51) | [web-api/31-ui-50-51.md](web-api/31-ui-50-51.md) |
| 데이터 저장소 백업·복원·용량·삭제 (UI-60·62·63) | [web-api/32-ui-60-62-63.md](web-api/32-ui-60-62-63.md) |
| 데이터 저장소 옮기기 (UI-64) | [web-api/33-ui-64.md](web-api/33-ui-64.md) |
| 데이터 저장소 파일 | [web-api/34-req-28.md](web-api/34-req-28.md) |
| 단독 컨테이너 (UI-3E·3F, REQ-29) | [web-api/35-ui-3e-3f-req-29.md](web-api/35-ui-3e-3f-req-29.md) |
| 상태 검사 스크립트와 정책 (UI-90·91) | [web-api/36-ui-90-91.md](web-api/36-ui-90-91.md) |
| AI 설정 (UI-B7, W2.1, 시스템 관리자) | [web-api/37-ai-ui-b7-w2-1.md](web-api/37-ai-ui-b7-w2-1.md) |
| AI 코디네이터 (UI-B0~B2, W2.2, 본인 대화만) | [web-api/38-ai-ui-b0-b2-w2-2.md](web-api/38-ai-ui-b0-b2-w2-2.md) |
| 장애 자동 대응 (UI-B3~B5·B8, W2.3) | [web-api/39-ui-b3-b5-b8-w2-3.md](web-api/39-ui-b3-b5-b8-w2-3.md) |
| 행동 지침 (UI-BA, W2.3a) | [web-api/40-ui-ba-w2-3a.md](web-api/40-ui-ba-w2-3a.md) |
| MCP 연동 (UI-B9, W2.3a) | [web-api/41-mcp-ui-b9-w2-3a.md](web-api/41-mcp-ui-b9-w2-3a.md) |
| 외부 접속 (UI-5A~5C, REQ-22) | [web-api/42-ui-5a-5c-req-22.md](web-api/42-ui-5a-5c-req-22.md) |
| 웹훅 (UI-BB·UI-44, W2.3b) | [web-api/43-ui-bb-ui-44-w2-3b.md](web-api/43-ui-bb-ui-44-w2-3b.md) |
| 공급자 진단 로그 (UI-C1, 시스템 관리자) | [web-api/45-provider-log.md](web-api/45-provider-log.md) |
| 아직 없는 것 (다음 단계) | [web-api/44-section.md](web-api/44-section.md) |
