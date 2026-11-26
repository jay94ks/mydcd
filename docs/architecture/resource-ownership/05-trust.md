## 서비스 진단의 trust와 임시 참조

| 자원 | 정의·변경 주체 | 소비·수명 |
|---|---|---|
| `service_cas` tenant CA bundle | 담당 노드 설치 설정의 시스템 관리자; CA 파일은 읽기 전용 | HTTPS 서비스 호출이 tenant 이름으로만 선택; app.yaml/사용자 경로 입력으로 변경하지 않으며 daemon 시작 시 읽음. Ingress 인증서 보관함·CertificateMaterial과 독립 |
| service-call Task read consumer | 실제 Task owner의 현재 사용자 권한 검사 후 기존 journal에 임시 예약 | HTTP 연결 종료 후 정확 pin 반환; 같은 daemon root의 새 프로세스는 종료된 이전 `service-call` pin만 정산하고 checker/다른 owner 참조는 보존 |
| cd-probe 임시 Git 객체 | 현재 Deploy 권한으로 기존 GitFetcher가 유한 메모리에서 읽음 | 고정 commit/file만 읽고 종료 시 해제; CD cache·candidate·app 자원/operation을 생성하지 않음 |

