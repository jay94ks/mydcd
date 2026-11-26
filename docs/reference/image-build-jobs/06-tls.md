## 빌드 TLS 신뢰 자료

아래 daemon 직접 pull 신뢰 자료는 SourceContent가 없는 기존 SDK 기록에 적용한다.
신규 owner-content 경로는 위 경계를 사용하며 daemon에는 source별 CA를 설치하지
않는다. 출력 publisher의 내장 registry TLS 검증은 계속 같은 명시 client를 사용한다.

member `image-build-base-tls-owner`는 원 `ImageBuildBaseRead`를 입력받아 외부 source의
공개 CA만 반환한다. 일반 사용자/Vault 원문 조회가 아니며 설치된 원 Builder→source owner의
MYDCP만 사용한다. 양쪽은 current quorum·running/unknown의 원 begin/reader/ReadSet을
검사한다. CA가 선언돼 있으면 인증서 누락을 거부하고, 선언되지 않은 CA를 임의로 추가하지
않는다. reader가 원 provider 값을 읽되 password·개인키·다른 Vault 값은 반환하지 않는다.

내장 base/output registry에는 member `image-build-registry-tls-owner`가 원
`ImageBuildRegistryPermit`을 입력받는다. 고정 Subject/Repository/Run·owner/generation/spec·
현재 serving certificate 지문을 검사한다. 반환 chain은 실제 원 TLS server가 보유한
인증서의 복사이며 key file·개인키를 읽어 전달하지 않는다. 원 builder의 managed token 교환과
출력 OCI publisher는 이 chain으로 명시 HTTPS client를 만든다. OS/Engine trust를 변경하지 않는다.

두 응답 형식은 `{Authority,Certificates:[base64 DER,...],Fingerprint:[32]}`다. 각 인증서는
X.509로 검증하며 최대128개·bundle64KiB 안에서 처리한다. managed Fingerprint는 현재
serving leaf의 SHA-256이고 첫 certificate와 일치해야 한다. 외부 CA는 Fingerprint가0이다.
토큰/password/keypair를 포함하지 않으며 invalid PEM·private-key block·임의 앞뒤 본문을 거부한다.

직접 pull하는 SDK 모드는 Create 전 optional `TLS:true`를 고정하고 `--config /input/buildkitd.toml`을
사용한다. 원 frozen Inputs의 authority만 TOML registry key에 허용하며 public CA와 설정은
context 밖 `/input/tls/registry-N.pem`·`/input/buildkitd.toml`의 root-owned 읽기 전용 파일이다.
plain HTTP·insecure skip verify·추가 mirror·keypair를 만들지 않는다. 입력 전체 trust 자료는
4MiB 이내이며 native journal에는 값 대신 optional Trust digest만 고정한다. 원 controls
전송 뒤 다른 trust로 재복사하지 않는다. 기존 TLS flag 없는 SDK/daemonless journal은
원 config와 JSON/closure 지문을 보존한다.

BuildKit daemon의 TLS 설정은 host 단위다. 같은 authority의 여러 source가 서로 다른 CA
집합(기본 trust와 custom CA의 혼합 포함)을 요구하면 임의 union/fallback을 하지 않고
충돌을 반환한다. 동일한 집합은 인증서/host 순서와 중복을 정규화해 재사용한다. 실제
권한 철회·source 변경·TLS 실패·정리와 rootless 경계의 성공 근거는 RQ6 마지막 검증 대상이다.

