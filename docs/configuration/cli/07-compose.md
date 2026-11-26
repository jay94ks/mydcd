## 관리 명령·Compose 선언·접속 수단

[관리 명령과 앱 선언의 경계](../../architecture/commands-and-declarations.md)를 따른다. app.yaml은 한 tenant의 이름 있는 앱 묶음·서비스 배치·앱 정책과 관리 망/Volume/Secret의 이름 참조를 담는다. 관리 망 자체·DNS/IPAM·Vault/Volume 정책 등 tenant 설정은 명시 관리 명령이 담당하며 앱 CD와 자동 병합하지 않는다. 로그인·계정/권한·Secret 원문 입력·backup/restore/이관 실행은 별도 명시 작업이다. `manage apply --change FILE`의 JSON은 typed 작업 요청이며 app.yaml이 아니다.

CLI 관리 전송은 MYDCP이며 원격 QUIC와 node.management_socket의 로컬 Unix TLS 어댑터가 같은 사용자 인증·tenant·CAS/quorum·원 결과 코어를 사용한다. MyDC 관리 socket의 기본값은 `/var/run/mydc.sock`, `docker_socket`은 Docker Engine 접속 경로다. Unix 파일 권한/UID로 사용자 인증을 생략하지 않는다. 앱 소유 설정의 직접 변경은 명시 override 계약을 따른다.

