# 컨테이너 Secret 공급

앱은 기존 Vault Secret/Group과 키를 참조한다. 값 입력·교체와 Group 승인은 별도 관리 작업이며, `app.yaml`에 원문·비밀번호·provider 자격을 넣지 않는다. 파일과 환경 변수 공급은 같은 현재 권한·원 승인·Binding·Task 세대를 사용한다.

이미지 빌드의 Secret mount는 [별도 build purpose](image-build-jobs/02-secret.md)로 같은 Vault 코어를 재사용한다. 앱 mount의 승인이나 파일/환경 키셋에 합치지 않으며 job 수락·terminal 정산에 사용 참조를 고정한다. CLI 로그인 키의 wallet은 이 공급 범위에 포함하지 않는다.

```yaml
services:
  api:
    # 이미지·노드·망 등 다른 필수 항목은 생략한 공급 방식 예시다.
    environment:
      SIGNING_KEY_FILE: /etc/app/signing.pem
    secrets:
      - source: signing-key
        target: /etc/app/signing.pem
        uid: "10001"
        gid: "10001"
        mode: "0400"
    x-sfc:
      secrets:
        from: [group/application-secrets]
        env:
          - source: database-password
            name: APP_DB_PASSWORD
secrets:
  signing-key:
    x-sfc: {key: SIGNING_KEY}
  database-password:
    x-sfc: {key: DB_PASSWORD}
```

`source`는 top-level `secrets` 별칭이다. `x-sfc.secrets.from`은 순서대로 병합할 Secret/Group 목록이며 마지막 키가 이긴다. 외부 Secret 별칭도 기존 이름 해석·승인 규칙을 따른다. 별칭이나 키가 없으면 다른 값으로 대체하지 않는다.

## 파일

상대 target은 `/run/secrets/` 아래로 정규화한다. 절대 target은 정규화된 비루트 경로여야 하며 최대 256바이트다. `/proc`·`/sys`·`/dev` 및 하위 경로, Docker의 `/etc/hosts`·`/etc/hostname`·`/etc/resolv.conf`와 그 상·하위 경로, `..`·NUL·개행·역슬래시는 거부한다. 다른 Secret 파일·Volume·tmpfs와 겹칠 수 없고 이미지가 선언한 Volume과도 겹칠 수 없다.

노드의 보호 projection 파일을 읽기 전용 bind로 공급한다. UID/GID와 0400/0440을 적용하며 앱이 호스트 원문 경로를 정하지 않는다. 파일의 원문은 바이너리여도 된다. 앱이 끝나도 빌린 Vault 객체를 삭제하지 않으며, 마지막 실제 소비자의 종료와 원 pin 반환 뒤 projection을 정리한다.

## 환경 변수

서비스의 `x-sfc.secrets.env`는 `{source, name}` 목록이다. `name`은 최대 256바이트의 `[A-Za-z_][A-Za-z0-9_]*`이며 중복을 허용하지 않는다. 일반 `environment`에 같은 이름이 있으면 `SECRET_ENV_CONFLICT`, 잘못된 이름/중복은 `INVALID_SECRET_ENV`, 없는 별칭/키는 `SECRET_BINDING_REQUIRED`로 계획을 거부한다.

값은 UTF-8·NUL 없음·키당 최대 64KiB이며 실제 환경 전체는 1MiB 이하다. 바이너리 개인키 등은 파일 공급을 사용한다. Secret은 이미지의 같은 이름 기본 환경 값을 교체하고, 앱의 일반 환경 값과 충돌하면 거부한다. 보호 projection은 데몬 소유 0600으로 보관하고 컨테이너에 마운트하지 않는다. Docker create에서만 값을 읽어 native 설정을 만들며 공유 Process/Task recipe·Raft·계획·관리 응답에는 값을 복사하지 않는다.

Docker Engine과 해당 컨테이너는 실제 환경 값을 보유한다. Docker/호스트 관리자 접근으로부터 값을 숨긴다는 보장은 아니다. 값·참조·공급 방식을 바꿀 때 새 Task 세대가 필요하다. 계획과 diff의 `SecretEnvRequiresNewGeneration`은 해당 서비스 이름 목록이며, 현재 실행에 환경 값을 직접 덮어쓰지 않는다.

## 로그

단발 logs와 follow는 원 Task의 검증된 projection에서 공급값을 읽고, stdout/stderr 각각에서 일치한 원문을 `«가림: tenant/Secret/키»`로 치환한 뒤 전달한다. 병합 결과의 실제 원 Secret을 표시하며, provenance가 없는 과거 projection은 키만 표시한다. Docker frame·네트워크 chunk에 걸친 값과 겹치는 값도 같은 필터를 거친다. 로그 끝의 미완성 Secret prefix는 가리고, 취소/오류 시 보류 중인 원문을 전송하지 않는다. 24KiB 응답 제한은 가림 뒤 출력에 적용한다.

공급값 합계가 8MiB를 초과하거나 원 projection을 검증/읽을 수 없으면 logs/follow를 거부한다. 이 경우 원문으로 fallback하지 않는다. 빈 값은 검색하지 않는다. 이 가림은 공급된 원문 바이트의 일치를 대상으로 하며 컨테이너가 변환·인코딩한 값까지 탐지하는 기능은 아니다. 일반 진단·Raft에 로그 본문이나 가림 matcher 상태를 보관하지 않는다.
