# Volume 파일 작업

`volume-file-put/list/get/delete`는 등록된 tenant/app Volume 아래 상대 경로만 다룬다. 파일 본문은 MYDCP purpose18의 유한 스트림으로 전달하며 operation에는 경로·길이·상한·digest·덮어쓰기 동의·원 native/consumer만 보존한다. 본문을 관리 이력이나 로그에 저장하지 않는다.

```sh
mydc volume files grant backup mydc-web-backups/ web-backup
mydc volume files put backup ./backup.db mydc-web-backups/today.db --max-size 256MiB
mydc volume files ls backup mydc-web-backups/
mydc volume files get backup mydc-web-backups/today.db ./recovered.db --max-size 256MiB
mydc volume files rm backup mydc-web-backups/today.db
mydc volume files revoke backup mydc-web-backups/ web-backup
```

볼륨 이름에 `앱/`이 없으면 사전 등록된 tenant Volume이다. 명령 전체는 [mydc volume](../cli/volume.md#파일-넣고-빼기)에 있다. 폴더 위임은 `volume files grant/revoke`로 tenant 관리자가 사용자에게 지정 Volume·접두어 아래 네 가지 파일 작업만 허용한다. 전역 사용자/credential을 편집하지 않는다. 실행 계정은 현재 tenant Read와 파일 operation ceiling을 만족해야 하며, credential에 별도 `VolumeFiles` ceiling이 있으면 그것도 동시에 만족해야 한다. 다른 경로·다른 Volume·다른 tenant에는 권한이 생기지 않는다. 일반 Volume manager는 현재 ManageVolumes 범위로 작업한다.

credential의 `VolumeFiles`는 선택적인 추가 ceiling이다. 항목은 `{Tenant,App,Volume,Prefix,Operations}`이며 Tenant·Volume·선택 App은 정확히 일치해야 하고 Prefix는 끝이 `/`인 canonical 상대 폴더다. App의 빈 값은 tenant 등록 Volume을 뜻하며 모든 앱을 뜻하지 않는다. Operations는 `volume-file-put/get/list/delete`의 명시 목록이다. ceiling을 생략한 nil은 기존 권한을 좁히지 않으며 명시적인 빈 배열 `VolumeFiles:[]`는 파일 작업 전체를 거부한다. 저장 credential과 공개 credential은 JSON roundtrip에서도 이 빈 배열을 유지한다. 기존 nil은 필드를 생략하고 비어 있지 않은 ceiling의 schema1 JSON 바이트는 유지한다. 원 사용자 operation payload에서도 빈 ceiling의 존재를 보존하며 원 서명을 다시 쓰거나 nil로 완화하지 않는다. 독립 사용자 Approval 키에도 ceiling이 있으면 현재 입력 credential과 함께 교집합으로 검사한다. ceiling 자체는 권한을 부여하지 않으므로 folder grant 회수 후 Read와 ceiling만으로 파일 작업을 계속할 수 없다. plan/status와 실제 purpose18 I/O가 같은 현재 `AuthorizeVolumeFile` 경계를 소비한다.

파일 작업은 기존 Volume writer/readers와 native pin을 사용한다. put/delete는 쓰기 consumer이며 앱 writer·move/restore와 충돌하면 거부된다. fixed Volume은 승인된 저장 root와 현재 tenant 정책을 확인한다. 경로는 pinned `os.Root`/openat2 아래에서 열며 절대 경로·`..`·symlink·hardlink·내부 staging 이름을 거부한다. 파일 크기는 최대 1GiB, 목록은 페이지당 64개이며 프레임은 유한 상한을 가진다.

put은 원 operation 전용 staging 파일을 쓰고 sync한 뒤 원 inode의 publication receipt를 private node DB에 저장하고 rename한다. 덮어쓰기는 명시 옵션이다. 응답 손실 뒤 같은 내용이 있다는 이유로 성공을 판정하지 않는다. 복구에는 원 operation/path/digest/device/inode publication receipt와 실제 공개 파일의 일치가 필요하다. 확인할 수 없으면 원 작업·native pin·consumer를 Unknown으로 보존한다.

get의 로컬 출력은 길이·digest·마지막 EOF를 확인한 뒤 게시한다. `file-status --request-id ID`와 `file-resume --request-id ID`는 원 journal을 사용한다. 완료한 I/O의 native 반환과 공유 consumer 정산은 사용자 자격 취소 뒤에도 원 owner receipt로 끝낼 수 있으며 새 파일 I/O를 허용하지 않는다.
