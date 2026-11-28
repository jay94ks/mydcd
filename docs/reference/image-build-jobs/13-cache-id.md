## cache ID별 보존 항목 조회

`sfcli build cache show CACHE --node NODE`는 목록에서 얻은
cache identity의 항목을 읽는다. `CACHE_HEX`는 32바이트 Cache의 소문자64자리 hex다.
기존 Job selector와 같은 사용자 메서드를 쓰며 selector를 혼합하지 않는다.

```text
Job 조회:   Query:{Job:"job-id"}
Cache 조회: Query:{Job:"",Cache:[32],Node:"node-id"}
Request = {Schema:1,Method:"image-build-cache",Nonce:[32],Params:{Tenant,
           Query,After?}}
Reply.Data = {Page,Tenant,Job,Context,Node,JobSnapshot:[32],
                        CacheScope?:[32],Epoch,Next}
```

두 형식은 정확히 하나만 허용한다. Cache 조회는 Node를 필수로 명시하고 현재 해당
tenant/node Read 또는 ManageRegistry를 확인한다. 같은 tenant/node의 보존 공유 job에서
일치하는 cache identity를 찾고 원 설치 owner를 검사한다. 다른 tenant/node의 cache나
0/누락 ID·혼합 selector는 허용하지 않는다. job 조회는 삭제된 job을 다시 열지 않는다.

Cache 조회는 삭제된 job/컨텍스트가 남긴 범위를 읽을 수 있다. 대표는 inventory와 같은
최신 CreatedAt/job-ID 순서로 선택하고 원 Spec을 공개하지 않는다. 응답 Job/JobSnapshot은
대표의 설명 정보다. optional CacheScope는 명시 선택한 cache identity이며 `Page.Cache`와
같다. cache cursor는 관측 Snapshot/cache identity/epoch/offset에 고정하고 대표 교체만으로
무효화하지 않는다. 실제 관측이 바뀌면 conflict다. 기존 job cursor는 계속 원 Spec digest에
고정하며 cache cursor와 서로 교환하지 않는다. 같은 최대32항목·24KiB와 관측/실패/Cleanup
의미를 사용한다.

새 queued 대표의 native 기록이 없어도 원 관측 job의 native record/SDK Sent/cache scope를
검사하고 기존 항목을 읽는다. 항목과 요약은 같은 원 증거 검사를 사용한다. 관측/원 cache
record·관측 job이 유실되거나 바뀐 경우 오류이며 빈 cache/새 namespace로 만들지 않는다.
조회로 원 native job·디렉터리·root pin을 생성하지 않는다. 아직 시작하지 않은 job의 전용
조회에서 기존 cache 증거만 발견되면 자료 불일치를 숨기지 않으므로, 공유 cache의 항목은
명시 cache selector를 사용한다.

member `image-build-cache-owner`는 기존 `{Session,Tenant,Query,After,Spec,Epoch}`에서 새
Query selector를 그대로 사용한다. cache 모드는 현재 대표가 바뀌어도 같은 cache identity/
설치 owner/권한을 전후 검증한다. 임의 Spec이나 q.Cache를 조회 권위로 취급하지 않는다.
이 메서드는 읽기이며 cache ID만으로 정리·삭제를 실행할 권한을 부여하지 않는다.


