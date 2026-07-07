


run_refiltered_v2_rebuild.sh
파일
뭐지 너가 짜준코드 실행 시켰는데 생성된 폴더 안에 db 실행 시키니까 테이블이 하나도 없다는데?
뭐가 잘못된거지? 아래는 로그값과, 테이블 리스트야

[START] 2026-07-03 08:09:51
[INFO] log file: logs/refiltered_v2_rebuild_20260703_080951.log
[INFO] project root: /home/flba/korea_univ/cve_matcher
[INFO] current dir: /home/flba/korea_univ/cve_matcher

[STEP 1] input checks
[OK] exists: ./data/filtered.json
[OK] exists: ./workspace/github_cache
[OK] exists: ./git
[OK] exists: ./scripts/02-04_refilteringNbuild_nvd2db.py
[OK] exists: ./scripts/02-05_apply_manual_overrides_and_partial_reindex.py
[OK] exists: manual_overrides

[INFO] manual override files:
total 388K
-rw-rw-r-- 1 flba flba  68K Jul  3 07:23 metadata_nonproduct_term_boundary_audit_accept.csv
-rw-rw-r-- 1 flba flba  79K Jul  3 07:23 mismatch_or_review_cve_github_pairs_accept.csv
-rw-rw-r-- 1 flba flba 4.3K Jul  3 07:23 mismatch_or_review_cve_github_pairs_reject.csv
-rw-rw-r-- 1 flba flba 226K Jul  3 07:23 review_inserted_manual_decision_accept.csv
-rw-rw-r-- 1 flba flba 2.6K Jul  3 07:23 review_inserted_manual_decision_reject.csv

[STEP 2] rebuild base DB with 02-04
[CMD] python ./scripts/02-04_refilteringNbuild_nvd2db.py --nvd-input ./data/filtered.json --github-cache ./workspace/github_cache --git-dir ./git --out-workspace workspace_refiltered_v2 --out-db-name version_cve_refiltered.db --force --write-audit
[NVD] reading /home/flba/korea_univ/cve_matcher/data/filtered.json
[PROGRESS] nvd_records=20000 accepted_refs=7070
[PROGRESS] nvd_records=30000 accepted_refs=10672
[PROGRESS] nvd_records=70000 accepted_refs=19954
[PROGRESS] cache_files_seen=1000
[PROGRESS] cache_files_seen=2000
[PROGRESS] cache_files_seen=3000
[PROGRESS] cache_files_seen=4000
[PROGRESS] cache_files_seen=5000
[PROGRESS] cache_files_seen=6000
[PROGRESS] cache_files_seen=7000
[PROGRESS] cache_files_seen=8000
[PROGRESS] cache_files_seen=9000
[PROGRESS] cache_files_seen=10000
[PROGRESS] cache_files_seen=11000
[PROGRESS] cache_files_seen=12000
[PROGRESS] cache_files_seen=13000
[PROGRESS] cache_files_seen=14000
[PROGRESS] cache_files_seen=15000
[PROGRESS] cache_files_seen=16000
[PROGRESS] cache_files_seen=17000
[PROGRESS] cache_files_seen=18000
[PROGRESS] cache_files_seen=19000
[PROGRESS] cache_files_seen=20000
[PROGRESS] cache_files_seen=21000
[PROGRESS] cache_files_seen=22000
[PROGRESS] cache_files_seen=23000
[PROGRESS] cache_files_seen=24000
[PROGRESS] cache_files_seen=25000
[PROGRESS] cache_files_seen=26000
[PROGRESS] cache_files_seen=27000
[PROGRESS] cache_files_seen=28000
[PROGRESS] cache_files_seen=29000
[PROGRESS] cache_files_seen=30000
[PROGRESS] cache_files_seen=31000
[PROGRESS] cache_files_seen=32000
[PROGRESS] indexed_pairs=1000/20762
[PROGRESS] indexed_pairs=2000/20762
[PROGRESS] indexed_pairs=3000/20762
[PROGRESS] indexed_pairs=4000/20762
[PROGRESS] indexed_pairs=5000/20762
[PROGRESS] indexed_pairs=6000/20762
[PROGRESS] indexed_pairs=7000/20762
[PROGRESS] indexed_pairs=8000/20762
[PROGRESS] indexed_pairs=9000/20762
[PROGRESS] indexed_pairs=10000/20762
[PROGRESS] indexed_pairs=11000/20762
[PROGRESS] indexed_pairs=12000/20762
[PROGRESS] indexed_pairs=13000/20762
[PROGRESS] indexed_pairs=14000/20762
[PROGRESS] indexed_pairs=15000/20762
[PROGRESS] indexed_pairs=16000/20762
[PROGRESS] indexed_pairs=17000/20762
[PROGRESS] indexed_pairs=18000/20762
[PROGRESS] indexed_pairs=19000/20762
[PROGRESS] indexed_pairs=20000/20762
[INFO] git sample allowlist repos=102306
[STEP 1] parse NVD, filter CPE/version/GitHub URLs, and score CPE↔GitHub mappings
[STEP 2] load GitHub versions/releases/commits from cache
[STEP 3] build version-CVE index from GitHub versions and selected NVD ranges
[STEP 4] write summary
[DONE] DB      = /home/flba/korea_univ/cve_matcher/workspace_refiltered_v2/version_cve_refiltered.db
[DONE] summary = /home/flba/korea_univ/cve_matcher/workspace_refiltered_v2/build_summary.json

[STEP 3] sqlite quick_check after 02-04
[quick_check] ok

[STEP 4] apply manual overrides and partial reindex with 02-05
[CMD] python ./scripts/02-05_apply_manual_overrides_and_partial_reindex.py --db workspace_refiltered_v2/version_cve_refiltered.db --csv-dir manual_overrides --builder-script ./scripts/02-04_refilteringNbuild_nvd2db.py --github-cache ./workspace/github_cache --nvd-input ./data/filtered.json --refresh-affected-ranges --backup --export-dir workspace_refiltered_v2/manual_override_exports
[NVD] reading /home/flba/korea_univ/cve_matcher/data/filtered.json
[PROGRESS] cache_files_seen=1000
[PROGRESS] cache_files_seen=2000
[PROGRESS] cache_files_seen=3000
[PROGRESS] cache_files_seen=4000
[PROGRESS] cache_files_seen=5000
[PROGRESS] cache_files_seen=6000
[PROGRESS] cache_files_seen=7000
[PROGRESS] cache_files_seen=8000
[PROGRESS] cache_files_seen=9000
[PROGRESS] cache_files_seen=10000
[PROGRESS] cache_files_seen=11000
[PROGRESS] cache_files_seen=12000
[PROGRESS] cache_files_seen=13000
[PROGRESS] cache_files_seen=14000
[PROGRESS] cache_files_seen=15000
[PROGRESS] cache_files_seen=16000
[PROGRESS] cache_files_seen=17000
[PROGRESS] cache_files_seen=18000
[PROGRESS] cache_files_seen=19000
[PROGRESS] cache_files_seen=20000
[PROGRESS] cache_files_seen=21000
[PROGRESS] cache_files_seen=22000
[PROGRESS] cache_files_seen=23000
[PROGRESS] cache_files_seen=24000
[PROGRESS] cache_files_seen=25000
[PROGRESS] cache_files_seen=26000
[PROGRESS] cache_files_seen=27000
[PROGRESS] cache_files_seen=28000
[PROGRESS] cache_files_seen=29000
[PROGRESS] cache_files_seen=30000
[PROGRESS] cache_files_seen=31000
[PROGRESS] cache_files_seen=32000
[BACKUP] /home/flba/korea_univ/cve_matcher/workspace_refiltered_v2/version_cve_refiltered.db.bak_manual_override_20260703_085741
[LOAD] override CSVs
{
  "read:metadata_accept:rows": 107,
  "read:metadata_accept:sha256": "678efbb456bf4a3e9fde225544aae10c253bb69a19beac87c5e5f39ecd1c820f",
  "read:mismatch_accept:rows": 71,
  "read:mismatch_accept:sha256": "a185b1bce2e672f9b40f4c028a69cf1d307f6a0a8b2a845332a57c6b65b9ff12",
  "read:mismatch_reject:rows": 4,
  "read:mismatch_reject:sha256": "461a169ad205db540485b522459a9b6f301d96733eb99b59c9fca113d9755f6f",
  "read:review_accept:rows": 183,
  "read:review_accept:sha256": "8e2cc622ff25b3de983ece8a149d459f53de9087a1cb4a808c9b0092da989d8c",
  "read:review_reject:rows": 2,
  "read:review_reject:sha256": "cb86d10799234d29229c137ff07deca45b0598897e4d824466caa9d7c38caab5",
  "repo_accept_rows": 107,
  "row_accept_rows": 254,
  "row_reject_rows": 4
}
[STEP 1] apply manual overrides
{
  "repo_accept_overrides": 107,
  "row_accept_refs_inserted_or_replaced": 254,
  "row_reject_overrides": 4,
  "version_index_rows_deleted_for_reject_products": 0,
  "reject_ref_kept_for_other_product_line": 2,
  "cve_github_refs_deleted_for_reject": 1,
  "static_correct_product_line_refs_inserted": 7
}
[INFO] affected_cves=244
[INFO] affected sample: CVE-2012-2671, CVE-2012-6662, CVE-2014-0083, CVE-2015-3152, CVE-2015-9242, CVE-2016-0546, CVE-2016-1000339, CVE-2016-1000340, CVE-2016-1000341, CVE-2016-1000342, CVE-2016-1000343, CVE-2016-1000344, CVE-2016-1000345, CVE-2016-1000346, CVE-2016-1000352, CVE-2016-10555, CVE-2016-10703, CVE-2016-6663, CVE-2016-8614, CVE-2017-1000068
[STEP 2] refresh affected nvd_cpe_ranges from NVD
{
  "nvd_target_records_seen": 244,
  "ranges_inserted": 557,
  "range_skip_no_version_info": 4
}
[STEP 3] reload GitHub cache into DB
{
  "cache_files_seen": 32546,
  "github_release_versions": 221521,
  "cache_item_skip_repo_not_selected": 1150066,
  "github_tag_versions": 876704
}
[STEP 4] partial reindex affected CVEs
{
  "old_version_index_deleted_for_affected_cves": 31609,
  "version_not_match:not_exact_cpe_version": 10989,
  "version_index_insert_attempt": 51170,
  "skip_product_line_allow_guard": 216,
  "version_not_match:above_or_equal_end_excluding": 34835,
  "version_not_match:above_end_including": 3884,
  "version_not_match:below_start_including": 27236,
  "skip_no_github_versions": 31
}
[STEP 5] export verification CSVs
[EXPORT] /home/flba/korea_univ/cve_matcher/workspace_refiltered_v2/manual_override_exports
[DONE]

[STEP 5] sqlite quick_check after 02-05
[quick_check] ok

[STEP 6] summary
repositories,3482
cves,20663
cve_github_refs,20948
nvd_cpe_ranges,64174
github_versions,1079133
github_commits,0
version_cve_index,14247788

[INFO] output DB: workspace_refiltered_v2/version_cve_refiltered.db
[INFO] export dir: workspace_refiltered_v2/manual_override_exports
[INFO] log file: logs/refiltered_v2_rebuild_20260703_080951.log
[DONE] 2026-07-03 09:23:17

(clovery310) flba@aigpu60:~/korea_univ/cve_matcher$ sqlite3 ./workspace_refiltered_v2/version_cve_refiltered.db 
SQLite version 3.53.2 2026-06-03 19:12:13
Enter ".help" for usage hints.
sqlite> .tqable
Error: unknown command or invalid arguments:  "tqable". Enter ".help" for help
sqlite> .table
build_summary      github_commits                      manual_cve_repo_reject_overrides       manual_keep_cve_repo_ref        nvd_cpe_ranges
cve_github_refs    github_versions                     manual_fix_deleted_cve_github_refs     manual_product_line_allow       repositories
cves               manual_cve_repo_accept_overrides    manual_fix_inserted_cve_github_refs    manual_repo_accept_overrides    version_cve_index
Program interrupted.
(clovery310) flba@aigpu60:~/korea_univ/cve_matcher$ sqlite3 ./workspace_refiltered_v2_corrupt_20260703_080438/version_cve_refiltered.db 
SQLite version 3.53.2 2026-06-03 19:12:13
Enter ".help" for usage hints.
sqlite> .tables


붙여넣은 텍스트 (1)(108).txt
문서
저장이 따로 되있는건 아닌건가?

rejected candidate pairs sample(1)


해당 reject candidate sample들은 왜 어떤 과정에서 생긴거지? 각각 분류하고 분석해줘 

review candidate pairs accept


해당 페어들은 reject 된것들 중에서 다시 분석해서 accept해도 될것으로 판단된것들이야 분석하고 이걸 accept 해도 될지 검증해줘

reject list


해당 reject 항목들 분석해서 왜 reject 되었는지 classification 및 설명 진행해줘

accept list


reject list(1)


각 리스트들 분석해서 accept 하고 reject하는게 적합한지 검토해줘


codes.tar.gz
파일

run_refiltered_v2_rebuild(1).sh
파일
해당 파일 압축 해재 하여 코드 및 분석 사항을 토대로, 최종적인 코드 작성할거야
기존에 실행시키던 파이프라인 참고해서, 최종적으로 codex_res 하위에 accept 리스트 안의 항목들을 추가적으로 db에 등록하도록 코드 짜줘
이때 다른 추가적인 코드 실행이 아닌 단일 코드 실행으로 기존의 db 스키마와 동일하도록 나와야 해(build_summary  cve_github_refs  cves  github_commits  github_versions  nvd_cpe_ranges  repositories  version_cve_index)
또한 기존의 02-01 ~ 02-05를 실행시키는게 아닌 단일 코드로 db가 완성되야해


03_query_cves_by_github_version(1).py
Python
아래의 추가 기능 반영해서 결과 db(sqlite 파일)을 통해 query 결과보여주도록 03_query_cves_by_github_version.py 코드 수정해줘
- 요구 사항 발생 및 추가 명령어 제안
    - 검색 기능과 listup 기능 분할 및 추가
    - 검색 기능
        - 기존의 검색 살짝 수정
            - --git_url {url} --version {version} 으로 검색 수행
            - --repo_key {repo_key(ex.owner@repo)} --version {version}으로 검색 수행
        - cve 기반 검색 기능 추가
            - --cve_id {cve_id(ex. CVE-2025-22923)} 로 검색 수행(이때 cve는 소문자일 수도 있음)
    - List up
        - --git_url {url} --ls or --repo_key {repo_key(ex.owner@repo)} --ls 호출 시 해당 레포지토리가 가지는 버전별 cve count 결과 출력
        - --git_url {url} --ls --version {version} or --repo_key {repo_key(ex.owner@repo)} --ls --version {version} 호출 시 해당 버전 cve 목록 전체 출력


result.tar.gz
파일
결과파일 압축 해제하고 accept과 reject이 정상적으로 잘 됬는지 검토해주고, review_candidate_pairs.csv는 왜 생겼으며, 해당 파일 및 reject 파일에 listup된 것들이 새로 추가한 codex 기반 accept 과정에서 추가되었는지 확인해줘


result.tar.gz(1).part-000
파일

result.tar.gz(1).part-001
파일
파일 하나 더 올릴거야 기다려


result.tar.gz(1).part-002
파일
분할압축된거 기반으로 압축 해제하여 DB 정상적으로 등록 되었는지 오분류 된게 없는지 분석해줘

분할 파일 3개를 합쳐서 압축 무결성부터 확인하고, 내부 DB/CSV를 기준으로 accept/reject/skipped/conflict, 최종 테이블, row count, 오분류 의심 항목을 교차 점검하겠습니다.


추가적으로 랩 미팅할때 자료로 쓰게 각 STEP 에서 accept reject review 등 지표값들을 표로 정리해줘

12s 동안 생각함
응, 네 말이 맞아. 코드 구현 자체에 근본적인 설계 문제가 있는 게 맞다.

다만 표현을 조금 정확히 하면, 문제는 “하나의 CPE만 보고 version range를 정의했다”라기보다는:

CVE-repo accept만 가지고,
그 repo에 적용 가능한 CPE range를 개별적으로 제한하지 않고,
같은 CVE에 들어 있는 모든 CPE range를 해당 repo에 적용해버린 것
이게 문제야.

원래 되어야 하는 구조
정상적인 구조는 이래야 해.

CVE-2023-48795
  ├─ net-ssh@net-ssh
  │    └─ net-ssh에 해당하는 CPE range만 적용
  │
  ├─ paramiko@paramiko
  │    └─ paramiko에 해당하는 CPE range만 적용
  │
  ├─ libssh2@libssh2
  │    └─ libssh2에 해당하는 CPE range만 적용
  │
  └─ bitvise/ssh_client
       └─ bitvise:ssh_client CPE range만 적용
즉 accept 판단은 단순히:

CVE ↔ repo
로 끝나면 안 되고, 반드시:

CVE ↔ repo ↔ CPE vendor/product/range
까지 묶여야 해.

현재 잘못된 구조
현재 구현은 사실상 이렇게 된 거야.

CVE-2023-48795에 net-ssh@net-ssh가 accept됨
        ↓
CVE-2023-48795의 모든 nvd_cpe_ranges를 가져옴
        ↓
net-ssh@net-ssh의 모든 GitHub version과 비교
        ↓
version_cve_index 생성
그러면 이런 잘못된 결합이 생김.

net-ssh@net-ssh
  ↔ bitvise:ssh_client < 9.33

net-ssh@net-ssh
  ↔ bitvise:ssh_server < 9.32

net-ssh@net-ssh
  ↔ openssh range

net-ssh@net-ssh
  ↔ crushftp range
이건 틀린 결과야.

net-ssh repo가 CVE와 관련 있는 건 맞을 수 있지만, bitvise:ssh_client < 9.33이라는 version range를 net-ssh tag에 적용하면 안 됨.

핵심 오류
현재 코드가 섞은 관계는 이거야.

CVE-repo evidence 관계
와

repo-CPE product/version range 관계
이 둘은 다르다.

예를 들어:

CVE-2023-48795 ↔ net-ssh@net-ssh
이건 맞을 수 있음.

하지만:

net-ssh@net-ssh ↔ bitvise:ssh_client < 9.33
이건 틀림.

그런데 코드가 이 둘을 충분히 분리하지 못해서 version_cve_index가 오염된 거야.

그래서 DB 설계도 부족했던 것
현재 핵심 테이블이 대략 이렇게 있지.

cve_github_refs
nvd_cpe_ranges
github_versions
version_cve_index
그런데 중간에 반드시 있어야 하는 테이블 또는 논리 구조가 빠져 있어.

필요한 건 이런 거야.

accepted_repo_cpe_ranges
또는 이름을 붙이면:

cve_repo_cpe_range_accepts
컬럼은 이런 식이어야 함.

cve_id
repo_key
range_id
range_key
vendor
product
decision_source
decision_reason
즉, 이 repo에 이 CPE range를 적용해도 된다는 명시적 binding이 필요함.

올바른 index 생성 조건
현재 잘못된 조건:

repo가 CVE에 연결되어 있으면
그 CVE의 모든 CPE range를 적용
수정해야 하는 조건:

repo와 CPE range가 accept된 pair일 때만
그 range를 repo version에 적용
즉 SQL/로직으로 보면 이렇게 되어야 함.

version_cve_index 생성 대상 =
github_versions
JOIN accepted_repo_cpe_ranges
  ON github_versions.repo_key = accepted_repo_cpe_ranges.repo_key
JOIN nvd_cpe_ranges
  ON accepted_repo_cpe_ranges.range_id = nvd_cpe_ranges.range_id
현재처럼:

github_versions
JOIN cve_github_refs ON repo_key
JOIN nvd_cpe_ranges ON cve_id
이렇게 하면 multi-product CVE에서 바로 터짐.

네 말에 대한 정확한 답
네가 말한:

cve-repo간 match accept 된 것들에 대한 개별적인 cpe range define이 되어야 하는데 그냥 단순 하나의 cpe만 보고 version range를 정의했다는거잖아?

거의 맞아. 더 정확히는:

CVE-repo accept 결과에 대해
repo별로 적용 가능한 CPE range binding을 따로 정의해야 하는데,
현재 코드는 CVE 단위의 CPE range 전체를 repo에 적용했다.
그래서 결론은:

응, 코드 자체의 문제 맞다.
특히 version_cve_index를 생성하는 reindex/build logic이 잘못됐다.
무엇을 고쳐야 하냐
우선순위는 이거야.

1. cve_github_refs는 evidence로만 유지
2. version_cve_index 생성에는 cve_github_refs만 쓰지 않기
3. accept_list/manual_override에서 repo-CPE-range binding 생성
4. version_cve_index는 accepted binding에 있는 range_id만 사용
5. CVE-2023-44487, CVE-2023-48795 같은 multi-product CVE는 전체 재색인 금지
6. redirect/404 evidence는 version index 대상과 분리
특히 핵심은 이거야.

CVE 단위 재색인 X
CVE-repo-CPE-range 단위 재색인 O
최종 결론
네 판단이 맞다.

현재 DB 구조 생성은 성공했지만, version_cve_index의 의미론적 정확성에는 코드 설계 문제가 있다.

문제의 본질은:

CVE와 repo가 연결됐다는 사실만으로
그 CVE의 모든 CPE version range를 repo에 적용한 것
이고, 이건 multi-product CVE에서 반드시 오분류를 만든다.

따라서 다음 코드는 반드시 고쳐야 한다.

02-04의 version index build 부분
02-05의 partial reindex 부분
codex accept 이후 partial reindex 부분
수정 방향은 accepted pair/range binding 기반으로만 version_cve_index를 생성하는 것이다.


위 분석사항들 반영해서 기존코드 재사용하지 않는 새로운 버전의 코드 작성해줘

이번에는 기존 02-04/02-05 로직을 호출하거나 복붙하지 않고, 핵심 설계를 바꾼 새 단일 빌더로 작성하겠습니다. 핵심은 CVE↔repo와 repo↔CPE range를 분리하고, version_cve_index는 명시적으로 accept된 CVE-repo-range binding만 사용하게 만드는 것입니다.


기존의 flow는 유지해야해

반영 방향은 이렇게 확정하겠습니다. 기존 단계 순서(기본 rule build → manual override → codex accept → 최종 prune)는 유지하되, 내부 구현은 새로 짜고, 핵심 버그였던 CVE 단위 CPE 전체 적용을 없애서 CVE-repo-range binding으로만 version_cve_index를 만들겠습니다.


그 뿐만 아니라 github_redirect_cve_github_match_pairs 출신 accept row 774개는 cve_github_refs에는 들어갔지만, 현재 repo_key 기준으로는 전부 version_cve_index가 0인 문제와 404 evidence accept 183개도 evidence-only로 cve 조회가 불가능한 문제, git allowlist 밖 repo 2개가 ref 테이블에 있는 문제 또한 해결해야해
위 문제들은 codex analysis 항목들 추가하는 과정에서 생긴 오류인것으로 예상되


