## 보존 버전의 파일 트리·Dockerfile 조회

`build context ls CONTEXT [--version N]`, `build context cat CONTEXT PATH [--version N]`는 현재 선택 tenant의 **삭제되지 않은 immutable version**을 읽는다. VERSION_HEX는 `build-versions`의 ID를 소문자 64자리 hex로 표현한 값이다. `--tenant`·`--after`를 지원하며 각 호출은 한 페이지만 JSON으로 출력한다. mutable draft 파일 경로나 호스트 경로를 조회하는 기능이 아니다.

같은 User purpose8 kind1 요청은 `{Schema:1,Method:"build-context-content",Tenant,ImageBuildContent:{Version:[32],Part:"tree"|"dockerfile"|"file",Path?,Offset?},After?,Nonce:[32]}`다. 일반 User 본문과 마찬가지로 고정 배열 `UserKey`의 영 값도 canonical JSON에 포함한다. 현재 Session의 tenant Read 또는 ManageRegistry·원 owner/node/root ACL을 검사한다. 원 upload가 consume된 version을 가리키고 실제 회수되지 않았어야 한다. 다른 tenant의 ID·삭제된 version·미소비/회수된 원 upload를 요청하면 내용을 반환하지 않는다. consume된 보존 version은 upload 전송 기한이 지나도 현재 사용자 권한으로 읽을 수 있다.

성공 Reply의 `ImageBuildContent`는 `{Page:{Schema:1,Version:[32],Tree:[32],Part,Offset,Total,Entries?,Data?,Next?,File?},Root:[32],Epoch,Next?}`다.

| Part | Offset/Total 단위 | 본문·한도 |
|---|---|---|
| `tree` | 항목 개수 | 최대8개의 `Entries:[{Path,Directory,Executable,Bytes,Digest:[32]}]`. canonical 상대 경로 순서이며 전체 최대16,384항목 |
| `dockerfile` | byte | 최대24,576 bytes의 `Data`(JSON base64). 등록 Dockerfile의 정확한 원 bytes이며 전체 최대1MiB |
| `file` | byte,64-bit | `Path`로 지정한 regular file의 `File:{Entry,Offset,Total,Next,Data?}`. Data는 최대24,576 bytes의 JSON base64, Entry는 tree와 같은 `{Path,Directory:false,Executable,Bytes,Digest:[32]}`다. 기존 Page.Offset/Total/Next는0이며 Entries/Data는 생략한다 |

tree/Dockerfile의 `Page.Next`, file의 `Page.File.Next`는 다음 numeric byte/entry offset이고 바깥 `Next`는 그 offset과 cluster/tenant/version/tree/Part/Path/epoch에 고정된 opaque cursor다. 마지막 페이지는 두 Next 모두 없거나 영 값이다. 클라이언트는 바깥 Next를 같은 선택자의 `After`로 보내고 현재 권한을 다시 검사한다. tree cursor를 Dockerfile 조회에 쓰거나 다른 version으로 바꾸면 conflict다. 조회 중 삭제가 확정되면 원 cursor도 사용할 수 없다. 일반 metadata의 root revision과 달리 무관한 컨텍스트 등록 변경으로 immutable 파일 페이지를 초기화하지 않는다.

owner가 다르면 기존 인증 member Management `image-build-content-owner`로 한 번 전달한다. owner는 fresh quorum으로 현재 권한/버전/epoch를 gate 전후와 반환 전에 확인하고, 이미 보유한 root dependency만 reopen한다. read-only spool 열기는 directory/DB evidence를 생성하거나 identity를 갱신하지 않는다. 원 ZIP 전체 SHA-256·ZIP/tree·Dockerfile 검사를 거친 트리 한 건만 메모리에 보관하며 새 DB나 ZIP 사본은 만들지 않는다. 매 페이지는 원 inode·크기·seal과 보존 pin을 확인하고, 원 자료 회수와 같은 gate 안에서 응답 bytes를 복사한다. 삭제 후에는 cache에 남은 bytes로 응답하지 않으며 native 회수 때 해당 cache도 비운다.

### 임의 regular file의 페이지와 EOF 확인

`Part:file`에는 canonical 상대 `Path`가 필수다. 첫 요청의 선택 `Offset:uint64`는 byte 위치이며 생략하면0이다. 후속 `After` cursor와0이 아닌 Offset을 함께 보내면 거부한다. 디렉터리·링크·장치·없는 항목·절대 경로·`../`는 반환하지 않는다. 파일의 Bytes/Executable/Digest는 원 inspected tree의 항목이며, 서버가 page마다 만든 새 파일 지문이 아니다. 응답의 `File.Total == File.Entry.Bytes`, `File.Offset`는 요청 위치, `File.Next`는 다음 byte 위치 또는 EOF의0이다. 빈 파일도 전체 길이0/빈 Data/Next0인 regular file로 구분한다. tree/Dockerfile의 기존 JSON·cursor와 필드 타입은 유지한다.

```sh
sfcli --tenant tenant-a build context cat source composer.json --version 3
# 전체 다운로드: 끝까지 받고 크기와 SHA-256을 확인한 뒤에만 파일을 남긴다.
sfcli --tenant tenant-a build context cat source composer.json --version 3 -O composer.json
```

owner의 기존 Content cache는 선택 regular file의 원 ZIP FD·decompressor·누적 hash를 최대1건 유지한다. 순차 Next 조회는 전체 O(n) 압축 해제/해시이고 EOF에서 원 entry 지문/CRC/길이를 확인한다. 임의 offset이나 파일 전환 뒤 조회는 해당 파일 처음부터 prefix를 건너뛰므로 O(offset)이며 현재 요청의 취소/시간 예산을 따른다. 전체 파일을 메모리나 별도 디스크 사본에 올리지 않는다. 원 artifact의 recorded pin·inode·seal을 매 요청 확인하고 cache 교체·오류·회수·Runtime 종료에서 reader를 닫는다. 원 version 삭제 뒤에는 남은 cache를 조회하지 않는다.

