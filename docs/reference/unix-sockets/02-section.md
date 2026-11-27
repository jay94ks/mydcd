## 설정과 접속

외부 registry의 공개 참조 조회는 기존 User의 `external-registries` 메시지다. 요청은 `{Schema:1,Method:"external-registries",Tenant,After?,Nonce}`이며 Node와 다른 selector는 허용하지 않는다. 현재 tenant Read 또는 ManageRegistry 권한을 검사한다. Reply는 `ExternalRegistriesRootRevision`, `ExternalRegistriesNext`, `ExternalRegistries:[{Spec,Revision,Deleted,Reader?}]`를 반환한다. 최대8행이며 Spec의 authority/repository/auth/Vault·CA 참조 필드는 [전체 형식](../external-registries.md)을 따른다. 값·원 operation/session은 반환하지 않는다.

등록·삭제는 새 socket을 만들지 않고 기존 사용자 서명 operation의 `put-external-registry`(`{Spec}`), `delete-external-registry`(`{Tenant,ID}`)로 실행한다. record/root CAS·원 결과/재개와 finite EOF 규칙을 유지한다. Unix 및 네트워크 SFCP는 같은 사용자 인증을 사용한다. 이 목록 메시지는 자격을 반환하지 않는다. source 승인과 로그인 시험은 아래 별도 User method를 사용한다.

노드 설정의 `node`에 지정한다. 이 예시는 기존 node 설정에 합칠 조각이다.

```yaml
node:
  management_socket: /run/sfcdp.sock
```

값을 생략하거나 listener에 빈 값을 전달하면 `/run/sfcdp.sock`을 사용한다. 지정 경로는 정규화된 절대 경로, `/` 이외, 최대107바이트여야 한다. `..` 등 정규화가 필요한 경로와 NUL·개행·탭·역슬래시·`?`·`#`·`%`는 거부한다. 추상 namespace 소켓이나 URI host/query/fragment를 받는 계약이 아니다.

CLI 등록 예시는 다음과 같다. 첫 세 줄은 같은 끝점의 대체 표기이므로 하나를 선택한다. 등록은 현재 Linux user의 `~/.sfc`에 적용된다.

```sh
sfcli context add local
sfcli context add local unix:///run/sfcdp.sock
sfcli context add local /run/sfcdp.sock
sfcli --cluster local login --user alice --method private-key --key operator
sfcli --cluster local --user alice whoami
```

endpoint 생략은 기본 Unix 소켓 선택이다. 절대 파일 경로 입력도 CLI가 Unix endpoint로 정규화한다. 실제 사용할 이름·키를 넣고 최초 신뢰 확인을 수행한다. 최초 키 등록과 계정 login은 각각 별도 절차다. context 사용법은 [context](../../cli/context.md)를 따른다.

