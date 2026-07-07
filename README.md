# NVD - Git 계정@레포명 매칭&DB 구축

- 타깃 DB 스키마
    
    ```sql
    SELECT vul_data.id_vul,
        vul_data.title,
        vul_data.file,
        vul_data.function id,
        vul_data.function length,
        vul_data.hash value,
        vul_data.cve_name,
        vul_data.cvss,
        vul_data.detected_counts,
        vul_data.oss_name,
        vul_data.cdb_id,
        vul_data.vul_file,
        vul_data.vul_datacol
    FROM sdb_db.vul_data;
    ```
    
- 전체 코드(26.07.01)
    
    [scripts.tar.gz](sub_files/scripts.tar.gz)
    

# 1. 파일 전처리 및 git version 정보 수집

- 폴더 구조
    - nvd-json-2.0: nvd 데이터 다운 경로
    - scripts : 실질적 스크립트 저장 위치
    - git : 검색 및 매치 시킬 github 데이터 list 파일들이 존재
    - workspace: 프로그램 실행 중 나오는 중간 파일 및 결과 파일 저장 장소
    - data: nvd 데이터 merge 해놓은 폴더(nvd_merged.json로 저장해 놓음)
    → **`00_merge_json.py`** 사용

## 1-1) ref github link exist case

- github 링크가 존재하는 cve들 필터링
- 없는 경우는 1-2로 토스
- 해당 cve를 필터링하여 github list와 매칭시켜서 별도 파일에 저장
git에 링크 존재 → `step_1_1_ref_github_matched.jsonl`
git에 링크 X → step_1_1_ref_github_unmatched.jsonl

## 1-2) cpe link convert matched case

- cpe에서 vendor;product 를 통해 github 리스트와 매칭
→ `step_1_2_cpe_matched.jsonl`
- 매치 되지 않는 경우 1-3으로 토스

## 1-3) remained case

- 별도의 json 파일로 저장, 추후 분석하여 재사용(지금은 별도의 파일로 저장만 해놓음)
→ `step_1_3_remained.jsonl`

⇒ **`01_splitNpreprocess.py`** 사용

*→ 데이터 분석 및 이전 설계 과정에서 사용되었음
⇒ 다음 DB 구축 과정에서는 그냥 merged.json만 사용함*

## 1-4) workspace/github_cache

- `build_version_cve_db.py`에서 수집
→ db 구축 후 완성 된 db 분석 과정에서 누락된 version 정보들 확인됨
→ 한 10시간 쯤 걸리는 듯
    - DB 1차 구축 이후 cache 재수집 진행하였음

# 2. DB 구축

- DB  목적
    - CVE/NVD baseline 정보
    - CVE와 GitHub repository 연결 정보
    - fix commit과 변경 함수 정보
    - tag/version별 코드 근거 정보
    - 최종 affected/fixed version range
- 최종 목표
    - 깃허브 링크와 버전 정보를 주면 자동으로 CVE가 list up 되는 것
- 진행 과정(26.07.02):
    - 1차 DB 구축: **`build_refonly_from_nvd_cache.py`**
        - git 하위에 listup 된 목록과 merged.json  파일 분석하여 github 링크가 ref에 참조 되어 있는것들 workspace/github_cache 에 수집
        - CVE별 references 검사
        - references.url에 `*github.com/owner/repo*` 형태가 직접 있는 CVE만 추출
        - cve_github_refs에 CVE ↔ repo 관계 등록
        → 해당 repo가 github_cache에 있으면 tag/release version 등록
        - NVD CPE range와 GitHub version을 비교
        - version_cve_index 생성
        - 생성 DB 분석
            - 생성된 인스턴스의 갯수 및 1개 이상의 cve가 할당된 레포 갯수 확인
            - cve 매칭된 repo의 version 정보 확인 과정에서 version 자체가 등록되지 않은 경우들을 확인하였음
            → 누락된 cache 재수집
            → 분석했던 데이터 2차 DB 구축 과정에서 날아감
    - git_cache 재수집
        - `02-02_make_ref_repo_fetch_targets.py`
        → DB의 cve_github_refs에 있는 검색 가능 repo만 선별
        - `02-03_fetch_missing_github_cache.py`
        → 선별된 repo 중 cache가 없는 것만 추가 다운로드
    - 2차 DB 구축: **`02-01_build_refonly_from_nvd_cache.py`**
        - 동일한 프로세스 유지, gitcache는 기존에 수집 및 누락된 것 재수집한 데이터 재사용
        - 생성 DB 분석
            - CPE에 version range 없는 CVE는 대부분 NVD 미분석 상태
                - 약 9107개의 cve가 깃허브 repo는 있는데, cpe range가 없음
                → nvd가 affected range를 설정하지 않은 경우임
                ⇒ 직접 들어가서 commit 따져보거나 실험해서 해결해야 함
                    ⇒ 이거 필요 없다고 하심 그냥 필터링 해서 싹 버리면 될듯
            - repo 링크가 있으나 version 정보 등록이 안되있는 경우
                - ref_repos_without_versions = 16410
                - cve가 등재된 제품의 공식 repo가 아닌 reference repo인 경우가 많음
                → version 정보가 없고, 있다고 한들 제품의 공식 repo가 아니기에 의미가 없음
            - `cve_github_refs`에 PoC/reference repo가 많이 들어감
                - ex. rapid7@metasploit-framework 와 같은 경우
                → https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/.. 로 등재 되어 있음
                ⇒ 오탐임
                    - 이는 PoC/advisory/exploit repo일 수 있음
                    **→ 위와 같은 경우들 필터링 해야함**
            - 최종적으로 version_cve_index로 완성되지 못하는 경우가 많음
                - GitHub ref repo가 제품 repo가 아니라 PoC/advisory repo임
                - repo는 맞지만 github_versions에 tag/release cache가 없음
                - NVD CPE range는 있지만 GitHub tag 형식과 비교가 안 됨
                - CPE product와 GitHub repo가 의미적으로 연결되지 않음
                - OS/distro CPE range가 섞여 있음
        - **최종 문제**: repo_key 즉, nvd 기반 등록된 repository는 총 20,838개
        하지만 cve 매칭된것은 4428개
        그 중에서도 repo가 [raw.githubusercontent.com](http://raw.githubusercontent.com) 인 것은 605개,
        poc/reference/adisory 로 **의심되는 것**은 5,643개임
            
            ⇒ 크게 나누자면 4종류로 나눠짐
            
            - product repo
                - 실제 취약 제품의 공식 repo
                - 예: apache@httpd, vim@vim, python@cpython
            - advisory/reference repo
                - 보안 권고, CVE DB, CSAF, advisory DB
                - 예: cisagov@csaf, rustsec@advisory-db
            - PoC/exploit/report repo
                - PoC, exploit, vulnerability report, 개인 CVE 모음
                - 예: rapid7@metasploit-framework, xxx@poc, xxx@cve
            - 그 외의 경우
                - 오타, 축약,순서 변경
                → 이걸 토큰 유사도로 계산하게 되면 다시 처음 부터 꼬임
                → llm에게 자동으로 들어가서 github 메인 repoo 찾으라 해보는건 어떤가?
                    1. rule-based로 확실한 것 accept/reject
                    2. 애매한 것만 MCP/RAG local LLM에 넘김
                    3. LLM 결과를 GitHub API/package metadata로 검증
                    4. confidence 낮은 건 manual review
                    5. 검증된 repo만 searchable_product_refs에 반영

# 3. query 예제 프로그램

- **`03_query_cves_by_github_version.py`**
    - `--github` 로 링크와 `--version` 으로 버전 정보만 넣어 주면 작동함
    ← 버전 정보는 정규화 과정을 고려하여 v를 붙여넣어고 되고 없애고 넣어도 됨
    - 해당 버전 대에서 발견된 cve 데이터를 가져옴
        
        ex) `python ./scripts/03_query_cves_by_github_version.py --github https://github.com/mongodb/mongo --version 2.6.0`
        
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
    - 최종 사용 방법
        - GitHub URL + version 검색
            
            `python 03_query_cves_by_github_version.py \
            --git_url [https://github.com/apache/httpd](https://github.com/apache/httpd) \
            --version 2.4.49` 
            
            https 안붙여도 되고, api, ssh, git url 다 됨
            
        - repo_key + version 검색
            
            `python 03_query_cves_by_github_version.py \
            --repo_key apache@httpd \
            --version 2.4.49`
            
        - CVE ID 기반 검색
            
            `python 03_query_cves_by_github_version.py \
            --cve_id cve-2025-22923`
            
        - repo별 version-CVE count list-up
            
            `python 03_query_cves_by_github_version.py \
            --repo_key apache@httpd --ls`
            
        - 특정 version의 CVE 전체 list-up
            
            `python 03_query_cves_by_github_version.py \
            --repo_key apache@httpd --ls --version 2.4.49`
            
        - JSON / CSV 출력
            - 마지막에 `--json-out query_result.json` 혹은 `--csv-out qery_result.csv`호출

# 99. 리뷰 항목

- [26.07.01](sub_files/26%2007%2001%20%EB%A6%AC%EB%B7%B0%20391e8cfac68c8079a831e129416ee2ea.md)
    - 질문
        1. cpe range 없다는게 version range 말씀인지? (version 정보가 아예 없는 경우는 데이터가 없으므로 연구 목적과 다름)
        → 버전 정보가 cpe에 등록되지 않은 경우가 있어서 따로 필터링 했었음
            연구 목적과 다르다면 먼저 해당 케이스 필터링 해도 될듯
        2. 실제 취약 제품의 공식 repo + 그 외 경우 (오타, 축약, 순서 변경) 이렇게 가는 게 좋을 것 같습니다. (PoC나 보안 권고 등은 프로덕트가 아니니까..)
        → centris 보고, 정확한 매칭 해야할 범위 인지가 필요한듯
    - 디스크립션이나 레퍼런스 url로 버전정보 가져올 수도 있음 고려 필요
    - 일단 github랑 정확히 매칭 + 오타, 축약, 순서변경 등의 케이스부터 고려
    → 프로덕트랑 직접적으로 관련된(HatBOM에서 나오는) 케이스만 필터링 하면 됨
    - 최종적인 목표: SBOM에서 “오픈소스 소프트웨어/컴포넌트의 버전별 CVE를 찾는 것”
    - github에서 나오는 repo들의 종류는 어떻게 되는가?
        - **product**: CVE가 실제로 영향을 주는 제품, 라이브러리, 서버, 프레임워크, CLI, 패키지의 공식 또는 사실상 upstream repo
        ex. java, go 프로덕트
        - **Product-adjacent repo**: 제품은 아니지만 주변 생태계, 취약 제품 자체가 아니라 주변 도구
        ex. sdk, plugin, 패키지 등
        - **PoC / Exploit repo**: 특정 cve를 재현하거나 공겨하는 코드→ 샘플에 많이 관찰됨
        ex. CVE 번호 포함(0vercl0k@cve-2019-11708), exploit 코드, 취약 앱 재현, 공격도구 등
        - **Advisory / Security database / Reference repo**: 취약점 정보를 모아둔 저장소
        ex. rustsec@advisory-db, cveproject@cvelist, csaf, vuln db
        - **Scanner / Detection / Rule repo**: 제품 소스가 아니라 탐지 룰, 스캐너, 점검 도구, 템플릿 저장소.
        ex. aquasecurity@trivy, 보안 분석 도구 등
        - **Example / Sample / Demo / Tutorial repo**: 예제, 데모, 튜터리얼 코드
        ex. aws-sample, ~-example, academind@~course-resoureces 등
        - **Documentation / Website / Book / Learning repo**: 문서, 책, 강의 자료 등
        ex. apachecn@python_data_analysis_and_mining_action, aquayi@leetcode~ 등
        - **Research / ML model / Academic repo:**  연구 관련 python, js 코드 레포 다량
        ex. deepmind@alphafold, automl@auto-sklearn 등
        - **Fork / Mirror / Archive / Deprecated repo**: 원본이 아닌 복제 및 보관용 레포
        ex. apache@attic-*, *-old, *-deprecated, legacy 등
    - **위 사항들을 반영한 필터링 rule 제안**
        1. cpe가 없는 케이스 필터링: cvss 만 존재하거나 둘다 없는 경우 counting
        2. cpe 내에 버전이 없는 케이스 필터링: 동일하게 counting 
        3. ref, cpe, descripion 내 url 순으로 체크하여 github link가 존재하는지 탐색
        필터링 된 것들은 counting
            - github 링크 필터링 규칙
                - **ACCEPT**
                    - `https://github.com/owner/repo` : 일반 레포
                        - `/repo` 하위에 뭐가 더 붙더라도 accept
                    - `https://github.com/owner/repo.git` : 일반 레포
                    - [`git@github.com](mailto:git@github.com):owner/repo.git`: ssh clone 형식
                    - `git+https://github.com/owner/repo.git`
                    - `ssh://git@github.com/owner/repo.git`
                    - [`https://api.github.com/repos/owner/repo/`](https://api.github.com/repos/owner/repo/): api endpoint
                    - [`https://codeload.github.com/owner/repo/](https://codeload.github.com/owner/repo/)...`: 아카이브 다운
                - **REJECT → 바로 reject 하는 것이 아닌 url 을 그냥 없애버리자!
                ⇒ 만약 다른 github 링크가 존재한다면 오작동 할 가능성을 없앰**
                    - [`https://raw.githubusercontent.com/owner/repo/`](https://raw.githubusercontent.com/owner/repo/): raw files
                    - [`https://github.com/advisories/GHSA-](https://github.com/advisories/GHSA-)...`
                    - [`https://github.com/topics/](https://github.com/topics/)...`
                    - [`https://github.com/marketplace/](https://github.com/marketplace/)...`
                    - [`https://github.com/collections/](https://github.com/collections/)...`
                    - [`https://github.com/explore/](https://github.com/explore/)...`
                    - [`https://gist.github.com/](https://gist.github.com/)...`: gist → product 아님
                    - [`https://owner.github.io/](https://owner.github.io/)...`: → html page ⇒ product 아님
        4. 추출한 url 및 데이터 전처리
            - undercase, 특수 문자(공백 포함) 통일화
        5. 토큰화를 통한 owner@product와 매치 필터링
            1. excact matched case ⇒ accept
            2. 비교용 키 생성: token key, compact key
            이때 token에서 중복을 제거하고 등록 및 compact key로 만듦
            compact key의 경우 리스트 내의 항목들을 사전순으로 이어붙임
            ex. secure-repo-repo⇒ [’secure’, ‘repo’], ‘reposecure’ 
            3. 비교용 토큰 생성
                - generic low- weight token: 일반적인 어미 등장 토큰
                →score 계산시 낮은 가중치 부여
                    
                    project, software, system, service, tool, tools, common, commons, main, base, utils, utility
                    
                - Soft non-product token: product 확률을 낮춤
                → score 계산시 음의 약한 가중치 부여
                    
                    sample, samples, demo, example, examples, tutorial, course, template, scaffold, starter, docs, documentation, website, awesome, test, tests, benchmark
                    
                - Hard non-product token: product 확률을 강하게 낮춤
                → score 계산시 음의 강한 가중치 부여
                    
                    poc, pocs, exploit, exploits, rce, cve, cves, vuln, vulnerability, advisory, advisories, writeup, writeups, metasploit, nuclei, oss-fuzz, cvelist
                    
            4. token 길이가 같을 시, 비교 실시
                1. token key를 통해 순서 변경 검사
                $Score_{token}(x,y)=
                \begin{cases}
                1.0 & T(x)=T(y) \text{ and order is same}\\
                0.95 & set(T(x))=set(T(y))\
                Score_{char}(x,y) & otherwise
                \end{cases}$
                2. compact key를 통해 순서 변경 감지
                    - char 2-gram 코사인 유사도와 Levenshtein Distance 사용
                    $Score_{char}(x,y)=\alpha \cdot LD_{sim}(x,y)+(1-\alpha)\cdot Cos_2(x,y)$
                        - vendor-owner: $a=0.8$
                        - product-repo: $a=0.5$
                        - $LD_{sim}(a, b) = 1 - \frac{\text{levenshtein\_distance}(a, b)}{ max(len(a), len(b))}$
            5. token 길이가 다를 시, 비교 실시
                1. generic low- weight token 내에 있는 항목을 제거
                    1. 길이가 같아짐 
                    ⇒ 각 제거 갯수마다 패널티 점수 부여 후 이전 “token 길이가 같을 시” 비교 단계 시행
                    $P_{generic}=0.03 \cdot N_{generic}\\
                    Score'=Score-P_{generic}$
                    2. 길이가 다름
                    ⇒ fitness score 계산
            6. fitness score 계산
                
                $OwnerScore=
                \begin{cases}
                1.0 & norm(vendor)=norm(owner)\\
                1.0 & T(vendor)=T(owner) \text{ and order is same}\\
                \max(OwnerRaw,0.95) & set(T(vendor))=set(T(owner))\\
                OwnerRaw & otherwise
                \end{cases}
                \\
                RepoScore=
                \begin{cases}
                1.0 & norm(product)=norm(repo)\\
                1.0 & T(product)=T(repo) \text{ and order is same}\\
                \max(RepoRaw,0.95) & set(T(product))=set(T(repo))\\
                RepoRaw & otherwise
                \end{cases}
                \\
                Penalty(T)=
                \min(
                0.03\cdot \#(T\cap Generic\ne\emptyset)
                \\+
                0.15\cdot \#(T\cap Soft\ne\emptyset)
                \\+
                0.35\cdot \#(T\cap Hard\ne\emptyset),
                0.50
                )
                \\
                \text{each Score'}=Score-Penalty
                \\
                FitnessScore=
                0.35\cdot OwnerScore'
                +
                0.65\cdot RepoScore'$ 
                
                - Soft non-product token과 Hard-non-product token 둘 다 포함되지 않는 경우 ⇒ accept
                - 그 외의 경우
                ⇒ threshold < 0.9 인 경우 reject&기록
        - 그런데 git sample 그 리스트만 쓰는건가?
        → 그렇다면 그냥 다 llm 한테 던져서 product인지 판단해서 1차 필터링 하는게 낫지 않는가?
    - 해야할것
        - [ ]  [CENTRIS 정리(HatBom)](sub_files/Centris%20391e8cfac68c8079b6e6c6bb28bcbfd6.md)
        - [ ]  Clovery 정리
    
- 26.07.02
    - **다른 사람에게 보여줄 자료 정리 방법**
        - 리뷰 받을려는 목적: 리뷰 해야할 것, 내가 지금 하는 것
        - 결과: 현재 프로젝트 진행 결과
        - 이유: 진행한 과정들을 한눈에 보이게 정리
    - **랩실 논문 리딩 및 관심분야 정하기**
- [26.07.06](sub_files/26%2007%2006%20392e8cfac68c808d9f04e0eb69037e53.md)
    - 404 에러 -> 패치 정보 없어도 일단 DB 등록
    - redirection -> 일단 HatBOM DB 기준으로 진행

# Bottom

[뻘짓](sub_files/%EB%BB%98%EC%A7%93%2038fe8cfac68c806ab38ec39f4afa0bd3.md)

[Centris](sub_files/Centris%20391e8cfac68c8079b6e6c6bb28bcbfd6.md)

- 리뷰 페이지
    
    [26.07.01 리뷰](sub_files/26%2007%2001%20%EB%A6%AC%EB%B7%B0%20391e8cfac68c8079a831e129416ee2ea.md)
    
    [26.07.06 ](sub_files/26%2007%2006%20392e8cfac68c808d9f04e0eb69037e53.md)