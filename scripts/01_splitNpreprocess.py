#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
split_nvd_github_cpe.py

목적
- data/nvd_merged.json 을 읽는다.
- git/ 하위의 GitHub repo list 파일들을 읽는다.
- CVE를 아래 3단계로 분리한다.
  1-1) NVD reference에 GitHub 링크가 있고, git list의 repo와 매칭되는 케이스
  1-2) 1-1에서 매칭되지 않은 CVE 중 CPE vendor/product로 git list repo와 매칭되는 케이스
  1-3) 끝까지 매칭되지 않은 CVE

입력
- NVD merged JSON: NVD API 2.0 형식(vulnerabilities[].cve)과 1.1 형식(CVE_Items[])을 모두 최대한 지원
- GitHub list: git/ 하위 파일들. 각 줄에 아래 형식 중 하나가 있어도 파싱
  - owner@repo
  - owner/repo
  - https://github.com/owner/repo
  - git@github.com:owner/repo.git

출력
- workspace/step_1_1_ref_github_matched.jsonl
- workspace/step_1_1_ref_github_unmatched.jsonl
- workspace/step_1_2_cpe_matched.jsonl
- workspace/step_1_3_remained.jsonl
- workspace/cve_repo_edges.csv
- workspace/repo_index.json
- workspace/match_summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse, unquote


GITHUB_HOSTS = {"github.com", "www.github.com"}
GITHUB_RE = re.compile(
    r"(?:https?://github\.com/|git\+https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
OWNER_AT_REPO_RE = re.compile(r"^(?P<owner>[A-Za-z0-9_.-]+)@(?P<repo>[A-Za-z0-9_.-]+)$")
OWNER_SLASH_REPO_RE = re.compile(r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)$")
CPE23_RE = re.compile(r"^cpe:2\.3:(?P<part>[^:]*):(?P<vendor>[^:]*):(?P<product>[^:]*):")

# GitHub URL에서 owner/repo 뒤에 자주 붙는 path segment들
GITHUB_REPO_STOP_SEGMENTS = {
    "commit",
    "commits",
    "pull",
    "pulls",
    "issues",
    "issue",
    "releases",
    "release",
    "tag",
    "tags",
    "tree",
    "blob",
    "raw",
    "compare",
    "security",
    "advisories",
    "wiki",
}


@dataclass(frozen=True)
class RepoInfo:
    owner: str
    repo: str
    repo_key: str       # owner@repo
    repo_full: str      # owner/repo
    repo_url: str
    source_file: str
    source_line: int
    owner_norm: str
    repo_norm: str


@dataclass(frozen=True)
class CpeInfo:
    cpe_uri: str
    part: str
    vendor: str
    product: str
    vendor_norm: str
    product_norm: str
    version: Optional[str] = None
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    vulnerable: Optional[bool] = None


@dataclass(frozen=True)
class RepoMatch:
    repo_key: str
    repo_full: str
    repo_url: str
    match_type: str
    score: float
    evidence: Dict[str, Any]


def norm_token(s: Optional[str]) -> str:
    """vendor/product/repo 비교용 normalize.

    - lower-case
    - URL escape 해제
    - CPE wildcard/NA 제거
    - 구분자 제거: '-', '_', '.', 공백 등
    """
    if not s:
        return ""
    s = unquote(str(s)).strip().lower()
    if s in {"*", "-", "n/a", "na", "none", "null"}:
        return ""
    # CPE escaped colon 등 최소 처리
    s = s.replace("\\:", ":")
    return re.sub(r"[^a-z0-9]+", "", s)


def clean_repo_name(repo: str) -> str:
    repo = repo.strip().strip("'\"`.,;:()[]{}<>")
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    return repo


def make_repo(owner: str, repo: str, source_file: str, source_line: int) -> Optional[RepoInfo]:
    owner = owner.strip().strip("'\"`.,;:()[]{}<>")
    repo = clean_repo_name(repo)
    if not owner or not repo:
        return None
    if owner.lower() in {"gist.github.com"}:
        return None
    owner_l = owner.lower()
    repo_l = repo.lower()
    return RepoInfo(
        owner=owner,
        repo=repo,
        repo_key=f"{owner_l}@{repo_l}",
        repo_full=f"{owner_l}/{repo_l}",
        repo_url=f"https://github.com/{owner}/{repo}",
        source_file=source_file,
        source_line=source_line,
        owner_norm=norm_token(owner),
        repo_norm=norm_token(repo),
    )


def parse_github_repo_from_text(text: str, source_file: str = "", source_line: int = 0) -> List[RepoInfo]:
    """문자열 하나에서 GitHub repo 후보를 추출한다."""
    repos: List[RepoInfo] = []
    text = text.strip()
    if not text or text.startswith("#"):
        return repos

    # 1) URL / git remote style
    for m in GITHUB_RE.finditer(text):
        info = make_repo(m.group("owner"), m.group("repo"), source_file, source_line)
        if info:
            repos.append(info)

    # 2) owner@repo 단독 라인
    if not repos:
        first = text.split()[0].strip().strip(",")
        m = OWNER_AT_REPO_RE.match(first)
        if m:
            info = make_repo(m.group("owner"), m.group("repo"), source_file, source_line)
            if info:
                repos.append(info)

    # 3) owner/repo 단독 라인
    if not repos:
        first = text.split()[0].strip().strip(",")
        # URL path가 아니라 순수 owner/repo일 때만
        if "://" not in first and "github.com" not in first:
            m = OWNER_SLASH_REPO_RE.match(first)
            if m:
                info = make_repo(m.group("owner"), m.group("repo"), source_file, source_line)
                if info:
                    repos.append(info)

    # 중복 제거
    seen = set()
    unique: List[RepoInfo] = []
    for r in repos:
        if r.repo_key not in seen:
            unique.append(r)
            seen.add(r.repo_key)
    return unique


def load_git_repo_index(git_dir: Path) -> Tuple[Dict[str, RepoInfo], Dict[str, List[RepoInfo]], Dict[str, List[RepoInfo]]]:
    """git/ 폴더의 모든 일반 파일에서 repo list를 읽고 인덱스를 만든다."""
    if not git_dir.exists():
        raise FileNotFoundError(f"git dir not found: {git_dir}")

    repo_by_key: Dict[str, RepoInfo] = {}
    by_repo_norm: Dict[str, List[RepoInfo]] = defaultdict(list)
    by_owner_norm: Dict[str, List[RepoInfo]] = defaultdict(list)

    files = sorted(p for p in git_dir.rglob("*") if p.is_file() and not p.name.startswith("._"))
    for path in files:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, 1):
                    for repo in parse_github_repo_from_text(line, str(path), line_no):
                        if repo.repo_key not in repo_by_key:
                            repo_by_key[repo.repo_key] = repo
        except OSError as e:
            print(f"[WARN] cannot read {path}: {e}", file=sys.stderr)

    for repo in repo_by_key.values():
        if repo.repo_norm:
            by_repo_norm[repo.repo_norm].append(repo)
        if repo.owner_norm:
            by_owner_norm[repo.owner_norm].append(repo)

    return repo_by_key, by_repo_norm, by_owner_norm


def load_nvd_items(nvd_path: Path) -> List[Dict[str, Any]]:
    """NVD merged JSON을 로드하고 CVE item 리스트로 반환한다."""
    if not nvd_path.exists():
        raise FileNotFoundError(f"NVD json not found: {nvd_path}")

    with nvd_path.open("r", encoding="utf-8", errors="ignore") as f:
        first = f.read(1)
        f.seek(0)
        # 일반 JSON object/list 우선 지원, 그 외는 jsonl로 처리
        if first in {"{", "["}:
            data = json.load(f)
            if isinstance(data, list):
                return data
        else:
            items = []
            for line in f:
                line = line.strip()
                if line:
                    items.append(json.loads(line))
            return items

    if isinstance(data, list):
        return data
    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
        return data["vulnerabilities"]
    if "CVE_Items" in data and isinstance(data["CVE_Items"], list):
        return data["CVE_Items"]
    if "cve" in data:
        return [data]

    raise ValueError("Unsupported NVD JSON shape. Expected vulnerabilities[], CVE_Items[], list, or cve object.")


def get_cve_obj(item: Dict[str, Any]) -> Dict[str, Any]:
    """NVD 2.0 item(vulnerabilities[].cve) 또는 1.1 item(cve)를 반환."""
    if "cve" in item and isinstance(item["cve"], dict):
        return item["cve"]
    return item


def get_cve_id(item: Dict[str, Any]) -> Optional[str]:
    cve = get_cve_obj(item)
    if cve.get("id"):
        return cve.get("id")
    meta = cve.get("CVE_data_meta") or {}
    if meta.get("ID"):
        return meta.get("ID")
    if item.get("cve_id"):
        return item.get("cve_id")
    if item.get("cve_name"):
        return item.get("cve_name")
    return None


def get_description(item: Dict[str, Any]) -> str:
    cve = get_cve_obj(item)

    # NVD 2.0
    descs = cve.get("descriptions")
    if isinstance(descs, list):
        for d in descs:
            if d.get("lang") == "en" and d.get("value"):
                return d["value"]
        if descs and descs[0].get("value"):
            return descs[0]["value"]

    # NVD 1.1
    desc_data = (((cve.get("description") or {}).get("description_data")) or [])
    if isinstance(desc_data, list):
        for d in desc_data:
            if d.get("lang") == "en" and d.get("value"):
                return d["value"]
        if desc_data and desc_data[0].get("value"):
            return desc_data[0]["value"]

    return ""


def get_cvss(item: Dict[str, Any]) -> Optional[float]:
    cve = get_cve_obj(item)
    metrics = cve.get("metrics") or item.get("impact") or {}

    # NVD 2.0: cvssMetricV31/V30/V2 list
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        vals = metrics.get(key)
        if isinstance(vals, list) and vals:
            cvss_data = vals[0].get("cvssData") or {}
            score = cvss_data.get("baseScore")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    pass

    # NVD 1.1 impact
    for key in ("baseMetricV3", "baseMetricV2"):
        val = metrics.get(key)
        if isinstance(val, dict):
            cvss_data = val.get("cvssV3") or val.get("cvssV2") or {}
            score = cvss_data.get("baseScore")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    pass
    return None


def iter_reference_urls(item: Dict[str, Any]) -> Iterator[str]:
    cve = get_cve_obj(item)

    # NVD 2.0: references: [{url, source, tags}]
    refs = cve.get("references")
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, dict) and r.get("url"):
                yield str(r["url"])

    # NVD 2.0 sometimes: references: {referenceData: [...]}
    if isinstance(refs, dict):
        for r in refs.get("referenceData") or refs.get("reference_data") or []:
            if isinstance(r, dict) and r.get("url"):
                yield str(r["url"])

    # NVD 1.1: cve.references.reference_data
    refs_obj = cve.get("references")
    refs1 = []
    if isinstance(refs_obj, dict):
        refs1 = refs_obj.get("reference_data") or []
    if isinstance(refs1, list):
        for r in refs1:
            if isinstance(r, dict) and r.get("url"):
                yield str(r["url"])

    # custom merged 형태 대비
    for key in ("references", "refs", "reference_urls"):
        val = item.get(key)
        if isinstance(val, list):
            for r in val:
                if isinstance(r, str):
                    yield r
                elif isinstance(r, dict) and r.get("url"):
                    yield str(r["url"])


def parse_github_repo_from_url(url: str) -> Optional[Tuple[str, str]]:
    """GitHub URL에서 owner/repo를 추출한다. commit/blob/issues 등의 하위 path는 제거."""
    raw = url.strip().strip("'\"`.,;:()[]{}<>")

    # git@github.com:owner/repo.git 같은 경우
    m = GITHUB_RE.search(raw)
    if m:
        return m.group("owner"), clean_repo_name(m.group("repo"))

    try:
        parsed = urlparse(raw)
    except Exception:
        return None

    host = parsed.netloc.lower()
    if host not in GITHUB_HOSTS:
        return None

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo in GITHUB_REPO_STOP_SEGMENTS:
        return None
    return owner, clean_repo_name(repo)


def extract_github_repos_from_refs(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    seen = set()
    for url in iter_reference_urls(item):
        parsed = parse_github_repo_from_url(url)
        if not parsed:
            continue
        owner, repo = parsed
        info = make_repo(owner, repo, "NVD.reference", 0)
        if not info:
            continue
        if info.repo_key in seen:
            continue
        repos.append({
            "owner": info.owner,
            "repo": info.repo,
            "repo_key": info.repo_key,
            "repo_full": info.repo_full,
            "repo_url": info.repo_url,
            "ref_url": url,
            "owner_norm": info.owner_norm,
            "repo_norm": info.repo_norm,
        })
        seen.add(info.repo_key)
    return repos


def split_cpe23(cpe_uri: str) -> Optional[Tuple[str, str, str, Optional[str]]]:
    """CPE 2.3 URI에서 part/vendor/product/version을 추출한다.

    CPE 2.3은 colon 구분자이지만 escaped colon이 있을 수 있으므로 최소한으로 처리한다.
    """
    if not cpe_uri or not cpe_uri.startswith("cpe:2.3:"):
        return None
    parts: List[str] = []
    cur = []
    esc = False
    for ch in cpe_uri:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))

    # cpe:2.3:a:vendor:product:version:...
    if len(parts) < 6:
        return None
    part = parts[2]
    vendor = parts[3]
    product = parts[4]
    version = parts[5] if len(parts) > 5 else None
    return part, vendor, product, version


def iter_dicts_deep(obj: Any) -> Iterator[Dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from iter_dicts_deep(v)
    elif isinstance(obj, list):
        for x in obj:
            yield from iter_dicts_deep(x)


def extract_cpes(item: Dict[str, Any]) -> List[CpeInfo]:
    """NVD item에서 CPE match들을 전부 추출한다."""
    candidates: List[CpeInfo] = []
    seen = set()

    # item 전체를 깊게 순회하면 NVD 1.1/2.0 구조 차이를 거의 흡수할 수 있다.
    for d in iter_dicts_deep(item):
        cpe_uri = d.get("criteria") or d.get("cpe23Uri") or d.get("cpe22Uri")
        if not isinstance(cpe_uri, str):
            continue
        parsed = split_cpe23(cpe_uri)
        if not parsed:
            continue
        part, vendor, product, version = parsed
        key = (
            cpe_uri,
            d.get("versionStartIncluding"),
            d.get("versionStartExcluding"),
            d.get("versionEndIncluding"),
            d.get("versionEndExcluding"),
        )
        if key in seen:
            continue
        seen.add(key)
        candidates.append(CpeInfo(
            cpe_uri=cpe_uri,
            part=part,
            vendor=vendor,
            product=product,
            vendor_norm=norm_token(vendor),
            product_norm=norm_token(product),
            version=version,
            version_start_including=d.get("versionStartIncluding"),
            version_start_excluding=d.get("versionStartExcluding"),
            version_end_including=d.get("versionEndIncluding"),
            version_end_excluding=d.get("versionEndExcluding"),
            vulnerable=d.get("vulnerable"),
        ))

    return candidates


def match_ref_github_repos(
    github_ref_repos: Sequence[Dict[str, Any]],
    repo_by_key: Dict[str, RepoInfo],
) -> List[RepoMatch]:
    """reference GitHub repo와 git list repo를 정확 매칭한다."""
    matches: List[RepoMatch] = []
    seen = set()
    for ref_repo in github_ref_repos:
        key = ref_repo["repo_key"]
        if key not in repo_by_key:
            continue
        if key in seen:
            continue
        repo = repo_by_key[key]
        matches.append(RepoMatch(
            repo_key=repo.repo_key,
            repo_full=repo.repo_full,
            repo_url=repo.repo_url,
            match_type="ref_github_exact_repo",
            score=1.0,
            evidence={
                "ref_url": ref_repo.get("ref_url"),
                "matched_ref_repo": ref_repo.get("repo_full"),
                "git_source_file": repo.source_file,
                "git_source_line": repo.source_line,
            },
        ))
        seen.add(key)
    return matches


def match_cpe_to_repos(
    cpes: Sequence[CpeInfo],
    repo_by_key: Dict[str, RepoInfo],
    by_repo_norm: Dict[str, List[RepoInfo]],
    by_owner_norm: Dict[str, List[RepoInfo]],
    min_score: float = 0.80,
    application_only: bool = True,
) -> List[RepoMatch]:
    """CPE vendor/product를 GitHub repo list와 매칭한다.

    보수적인 기준:
    - vendor/product가 owner/repo와 정확히 맞으면 1.00
    - vendor normalize + product normalize가 owner/repo와 맞으면 0.95
    - product가 repo명과 정확/정규화 기준으로 유일하게 맞으면 0.90/0.85
    - vendor만 owner와 맞는 것은 단독으로는 false positive가 많아 채택하지 않음
    """
    raw_matches: Dict[str, RepoMatch] = {}

    for cpe in cpes:
        if application_only and cpe.part and cpe.part != "a":
            continue
        if cpe.vulnerable is False:
            continue
        if not cpe.vendor_norm or not cpe.product_norm:
            continue

        # 1) cpe vendor/product == owner/repo 직접 매칭
        exact_key = f"{cpe.vendor.lower()}@{cpe.product.lower()}"
        if exact_key in repo_by_key:
            repo = repo_by_key[exact_key]
            m = RepoMatch(
                repo_key=repo.repo_key,
                repo_full=repo.repo_full,
                repo_url=repo.repo_url,
                match_type="cpe_exact_owner_product_to_repo",
                score=1.0,
                evidence={"cpe": asdict(cpe), "git_source_file": repo.source_file, "git_source_line": repo.source_line},
            )
            raw_matches[repo.repo_key] = choose_better(raw_matches.get(repo.repo_key), m)
            continue

        # 2) normalized owner/product == normalized owner/repo
        candidate_owners = by_owner_norm.get(cpe.vendor_norm, [])
        for repo in candidate_owners:
            if repo.repo_norm == cpe.product_norm:
                m = RepoMatch(
                    repo_key=repo.repo_key,
                    repo_full=repo.repo_full,
                    repo_url=repo.repo_url,
                    match_type="cpe_norm_owner_product_to_repo",
                    score=0.95,
                    evidence={"cpe": asdict(cpe), "git_source_file": repo.source_file, "git_source_line": repo.source_line},
                )
                raw_matches[repo.repo_key] = choose_better(raw_matches.get(repo.repo_key), m)

        # 3) product -> repo name exact/normalized. 단, 유일한 repo일 때만 자동 채택.
        product_repos = by_repo_norm.get(cpe.product_norm, [])
        if len(product_repos) == 1:
            repo = product_repos[0]
            same_owner = repo.owner_norm == cpe.vendor_norm
            score = 0.90 if not same_owner else 0.95
            mtype = "cpe_unique_product_to_repo" if not same_owner else "cpe_unique_product_same_owner_to_repo"
            m = RepoMatch(
                repo_key=repo.repo_key,
                repo_full=repo.repo_full,
                repo_url=repo.repo_url,
                match_type=mtype,
                score=score,
                evidence={"cpe": asdict(cpe), "git_source_file": repo.source_file, "git_source_line": repo.source_line},
            )
            raw_matches[repo.repo_key] = choose_better(raw_matches.get(repo.repo_key), m)
        elif len(product_repos) > 1:
            # 같은 product repo가 여러 owner에 존재하면 vendor==owner인 후보만 채택
            narrowed = [r for r in product_repos if r.owner_norm == cpe.vendor_norm]
            if len(narrowed) == 1:
                repo = narrowed[0]
                m = RepoMatch(
                    repo_key=repo.repo_key,
                    repo_full=repo.repo_full,
                    repo_url=repo.repo_url,
                    match_type="cpe_ambiguous_product_narrowed_by_vendor",
                    score=0.93,
                    evidence={
                        "cpe": asdict(cpe),
                        "ambiguous_product_repo_count": len(product_repos),
                        "git_source_file": repo.source_file,
                        "git_source_line": repo.source_line,
                    },
                )
                raw_matches[repo.repo_key] = choose_better(raw_matches.get(repo.repo_key), m)

    matches = [m for m in raw_matches.values() if m.score >= min_score]
    matches.sort(key=lambda x: (-x.score, x.repo_key))
    return matches


def choose_better(old: Optional[RepoMatch], new: RepoMatch) -> RepoMatch:
    if old is None:
        return new
    if new.score > old.score:
        return new
    # 점수가 같으면 match_type 문자열이 더 구체적인 쪽을 안정적으로 선택
    if new.score == old.score and len(new.match_type) > len(old.match_type):
        return new
    return old


def cve_summary(item: Dict[str, Any]) -> Dict[str, Any]:
    cve_id = get_cve_id(item)
    return {
        "cve_id": cve_id,
        "description": get_description(item),
        "cvss": get_cvss(item),
        "reference_urls": sorted(set(iter_reference_urls(item))),
        "cpes": [asdict(c) for c in extract_cpes(item)],
    }


def build_record(
    item: Dict[str, Any],
    stage: str,
    matches: Sequence[RepoMatch],
    extra: Optional[Dict[str, Any]] = None,
    include_raw_cve: bool = False,
) -> Dict[str, Any]:
    cve_id = get_cve_id(item)
    rec: Dict[str, Any] = {
        "cve_id": cve_id,
        "stage": stage,
        "matches": [asdict(m) for m in matches],
        "summary": cve_summary(item),
    }
    if extra:
        rec.update(extra)
    if include_raw_cve:
        rec["raw_nvd_item"] = item
    return rec


def write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> int:
    count = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=False) + "\n")
            count += 1
    return count


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def write_edges_csv(path: Path, records: Sequence[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "cve_id",
        "stage",
        "repo_key",
        "repo_full",
        "repo_url",
        "match_type",
        "score",
        "evidence_cpe_uri",
        "evidence_cpe_vendor",
        "evidence_cpe_product",
        "evidence_ref_url",
    ]
    count = 0
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for rec in records:
            for m in rec.get("matches", []):
                evidence = m.get("evidence") or {}
                cpe = evidence.get("cpe") or {}
                row = {
                    "cve_id": rec.get("cve_id"),
                    "stage": rec.get("stage"),
                    "repo_key": m.get("repo_key"),
                    "repo_full": m.get("repo_full"),
                    "repo_url": m.get("repo_url"),
                    "match_type": m.get("match_type"),
                    "score": m.get("score"),
                    "evidence_cpe_uri": cpe.get("cpe_uri"),
                    "evidence_cpe_vendor": cpe.get("vendor"),
                    "evidence_cpe_product": cpe.get("product"),
                    "evidence_ref_url": evidence.get("ref_url"),
                }
                w.writerow(row)
                count += 1
    return count


def run(args: argparse.Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    nvd_path = Path(args.nvd).resolve() if args.nvd else project_root / "data" / "nvd_merged.json"
    git_dir = Path(args.git_dir).resolve() if args.git_dir else project_root / "git"
    out_dir = Path(args.out_dir).resolve() if args.out_dir else project_root / "workspace"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] project_root = {project_root}")
    print(f"[INFO] nvd_path     = {nvd_path}")
    print(f"[INFO] git_dir      = {git_dir}")
    print(f"[INFO] out_dir      = {out_dir}")

    repo_by_key, by_repo_norm, by_owner_norm = load_git_repo_index(git_dir)
    if not repo_by_key:
        raise RuntimeError(f"No GitHub repositories parsed from {git_dir}")
    print(f"[INFO] loaded git repos = {len(repo_by_key):,}")

    dump_json(out_dir / "repo_index.json", {
        "repo_count": len(repo_by_key),
        "repos": [asdict(r) for r in sorted(repo_by_key.values(), key=lambda x: x.repo_key)],
    })

    items = load_nvd_items(nvd_path)
    print(f"[INFO] loaded NVD items = {len(items):,}")

    step_1_1_matched: List[Dict[str, Any]] = []
    step_1_1_unmatched: List[Dict[str, Any]] = []
    step_1_2_matched: List[Dict[str, Any]] = []
    step_1_3_remained: List[Dict[str, Any]] = []

    counters = Counter()

    for idx, item in enumerate(items, 1):
        cve_id = get_cve_id(item)
        if not cve_id:
            counters["missing_cve_id"] += 1
            cve_id = f"UNKNOWN-{idx}"

        github_ref_repos = extract_github_repos_from_refs(item)
        ref_matches = match_ref_github_repos(github_ref_repos, repo_by_key)

        if ref_matches:
            counters["step_1_1_ref_matched_cves"] += 1
            counters["step_1_1_ref_matched_edges"] += len(ref_matches)
            step_1_1_matched.append(build_record(
                item,
                stage="1-1_ref_github_matched",
                matches=ref_matches,
                extra={"github_ref_repos": github_ref_repos},
                include_raw_cve=args.include_raw_cve,
            ))
            continue

        if github_ref_repos:
            counters["step_1_1_ref_exists_but_not_in_git_list"] += 1
            step_1_1_unmatched.append(build_record(
                item,
                stage="1-1_ref_github_unmatched",
                matches=[],
                extra={"github_ref_repos": github_ref_repos},
                include_raw_cve=args.include_raw_cve,
            ))
        else:
            counters["no_github_ref"] += 1

        # 1-1에서 성공하지 못한 CVE는 1-2 CPE fallback으로 이동
        cpes = extract_cpes(item)
        cpe_matches = match_cpe_to_repos(
            cpes,
            repo_by_key,
            by_repo_norm,
            by_owner_norm,
            min_score=args.min_cpe_score,
            application_only=not args.allow_non_application_cpe,
        )
        if cpe_matches:
            counters["step_1_2_cpe_matched_cves"] += 1
            counters["step_1_2_cpe_matched_edges"] += len(cpe_matches)
            step_1_2_matched.append(build_record(
                item,
                stage="1-2_cpe_link_convert_matched",
                matches=cpe_matches,
                extra={
                    "fallback_from": "github_ref_unmatched" if github_ref_repos else "no_github_ref",
                    "github_ref_repos": github_ref_repos,
                },
                include_raw_cve=args.include_raw_cve,
            ))
        else:
            counters["step_1_3_remained_cves"] += 1
            step_1_3_remained.append(build_record(
                item,
                stage="1-3_remained",
                matches=[],
                extra={
                    "remained_reason": "no_ref_match_and_no_cpe_match",
                    "github_ref_repos": github_ref_repos,
                },
                include_raw_cve=args.include_raw_cve,
            ))

        if args.progress_every and idx % args.progress_every == 0:
            print(f"[INFO] processed {idx:,}/{len(items):,} CVEs ...")

    n_11 = write_jsonl(out_dir / "step_1_1_ref_github_matched.jsonl", step_1_1_matched)
    n_11u = write_jsonl(out_dir / "step_1_1_ref_github_unmatched.jsonl", step_1_1_unmatched)
    n_12 = write_jsonl(out_dir / "step_1_2_cpe_matched.jsonl", step_1_2_matched)
    n_13 = write_jsonl(out_dir / "step_1_3_remained.jsonl", step_1_3_remained)

    edge_count = write_edges_csv(out_dir / "cve_repo_edges.csv", step_1_1_matched + step_1_2_matched)

    summary = {
        "input": {
            "project_root": str(project_root),
            "nvd_path": str(nvd_path),
            "git_dir": str(git_dir),
            "out_dir": str(out_dir),
            "min_cpe_score": args.min_cpe_score,
            "application_only": not args.allow_non_application_cpe,
            "include_raw_cve": args.include_raw_cve,
        },
        "counts": {
            "git_repo_count": len(repo_by_key),
            "nvd_item_count": len(items),
            "step_1_1_ref_github_matched_jsonl_records": n_11,
            "step_1_1_ref_github_unmatched_jsonl_records": n_11u,
            "step_1_2_cpe_matched_jsonl_records": n_12,
            "step_1_3_remained_jsonl_records": n_13,
            "cve_repo_edge_csv_rows": edge_count,
            **dict(counters),
        },
        "output_files": {
            "repo_index": str(out_dir / "repo_index.json"),
            "step_1_1_ref_github_matched": str(out_dir / "step_1_1_ref_github_matched.jsonl"),
            "step_1_1_ref_github_unmatched": str(out_dir / "step_1_1_ref_github_unmatched.jsonl"),
            "step_1_2_cpe_matched": str(out_dir / "step_1_2_cpe_matched.jsonl"),
            "step_1_3_remained": str(out_dir / "step_1_3_remained.jsonl"),
            "cve_repo_edges": str(out_dir / "cve_repo_edges.csv"),
        },
    }
    dump_json(out_dir / "match_summary.json", summary)

    print("\n[DONE] split finished")
    print(json.dumps(summary["counts"], ensure_ascii=False, indent=2))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Split NVD CVEs into ref GitHub matched, CPE matched, and remained cases."
    )
    p.add_argument("--project-root", default=".", help="project root. default: current directory")
    p.add_argument("--nvd", default=None, help="NVD merged JSON path. default: <project-root>/data/nvd_merged.json")
    p.add_argument("--git-dir", default=None, help="GitHub list directory. default: <project-root>/git")
    p.add_argument("--out-dir", default=None, help="output directory. default: <project-root>/workspace")
    p.add_argument("--min-cpe-score", type=float, default=0.80, help="minimum score for CPE matching. default: 0.80")
    p.add_argument("--allow-non-application-cpe", action="store_true", help="also use CPE part != a. default: only application CPE")
    p.add_argument("--include-raw-cve", action="store_true", help="include full raw NVD item in each output JSONL record")
    p.add_argument("--progress-every", type=int, default=10000, help="print progress every N CVEs. 0 disables")
    return p


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(run(args))
    except KeyboardInterrupt:
        print("\n[ERROR] interrupted", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
