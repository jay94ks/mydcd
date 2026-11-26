## 파일 권한과 소유권

- 부모 디렉터리는 이미 존재해야 한다. root 또는 daemon의 effective UID가 소유하고 group/other 쓰기 권한이 없어야 한다.
- 소켓 파일은 **0600**으로 생성한다. OS 파일 권한에 따라 접속 가능한 Linux user가 정해진다.
- 기동 시 같은 경로에 기존 파일·symlink가 있거나 다른 daemon이 listen 중인 socket이 있으면 거부한다. 다른 daemon의 listener를 채택하지 않는다.
- 예외는 비정상 종료가 남긴 stale socket이다. 같은 사용자 소유 socket이고 연결이 거부(`ECONNREFUSED`)되면 지우고 새로 bind한다.
- 커널 `SO_PEERCRED`에서 실제 상대 UID를 읽는다. `unix-uid:<UID>`는 자격/Group 비밀번호 확인의 source budget이며 MyDC 관리 권한을 부여하지 않는다. UID0도 사용자 인증·tenant 권한·현재 정책을 따른다.
- 종료 시 생성한 inode를 pin으로 대조한 뒤 자기 소켓만 제거한다. 교체된 타인 파일/소켓은 보존한다.

`mydcd`는 설치 복구 뒤 관리 listener를 연다. 기동 이벤트의 `management_socket`에서 실제 주소를 확인할 수 있다. listener가 열렸다는 사실과 현재 Raft leader/quorum·앱 Healthy는 별도다.

