#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
02-04_refilteringNbuild_nvd2db.py

목표
----
NVD merged JSON/JSONL + GitHub cache를 이용해 기존 DB와 동일한 스키마로
version-CVE 검색 DB를 다시 빌드한다.

02-01과 동일한 DB 스키마를 유지하되, CVE↔GitHub repo 매핑 생성 정책을 다음과 같이 확장한다.

정책
----
1. CPE가 없는 CVE는 skip하고 counting한다.
   - CVSS만 존재하는 no-CPE case
   - CPE/CVSS 둘 다 없는 case
2. CPE는 있으나 usable version/range 정보가 없는 CVE는 skip하고 counting한다.
3. GitHub repo URL은 ref -> cpe/configuration -> description 순서로 탐색한다.
   - Reject URL은 record reject가 아니라 URL만 제거한다.
4. 후보 GitHub owner/repo와 CPE vendor/product를 문자열 유사도 기반으로 scoring한다.
   - vendor-owner alpha = 0.8 기본값
   - product-repo alpha = 0.5 기본값
   - char n-gram cosine은 n=2 기본값
   - final fitness threshold = 0.90 기본값
5. soft/hard non-product token이 포함된 후보는 기본적으로 DB 삽입하지 않고 counting/audit한다.
6. 기존 02-01과 동일 스키마로 다음 테이블을 생성한다.
   - repositories
   - cves
   - cve_github_refs
   - nvd_cpe_ranges
   - github_versions
   - github_commits
   - version_cve_index
   - build_summary

주의
----
- --git-dir 또는 --git-list가 주어지면 sample git list를 allowlist로 사용한다.
- allowlist 사용 시 sample list에 존재하는 repo만 최종 DB에 등록한다.
- NVD 내부 evidence(ref/cpe/description)에서 repo 후보를 만들되, allowlist 밖 repo는 제거한다.
- GitHub API는 호출하지 않는다. --github-cache 아래의 기존 tags/releases/commits cache만 읽는다.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import re
import sqlite3
import sys
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)


# ------------------------------------------------------------
# Constants / token classes
# ------------------------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

GENERIC_LOW_WEIGHT_TOKENS = {
    "project", "software", "system", "service", "tool", "tools",
    "common", "commons", "main", "base", "utils", "utility",
}

SOFT_NON_PRODUCT_TOKENS = {
    "sample", "samples", "demo", "example", "examples", "tutorial",
    "course", "template", "scaffold", "starter", "docs", "documentation",
    "website", "awesome", "test", "tests", "benchmark",
}

HARD_NON_PRODUCT_TOKENS = {
    "poc", "pocs", "exploit", "exploits", "rce", "cve", "cves",
    "vuln", "vulnerability", "advisory", "advisories", "writeup",
    "writeups", "metasploit", "nuclei", "oss", "fuzz", "ossfuzz",
    "oss-fuzz", "cvelist",
}

WILDCARD_VERSIONS = {
    "", "*", "-", "n/a", "na", "any", "all", "unspecified", "null", "none"
}

OWNER_REPO_AT_RE = re.compile(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+$")
OWNER_REPO_SLASH_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


# ------------------------------------------------------------
# GitHub URL regex
# ------------------------------------------------------------

TRAILING_PUNCT = ".,;:!?)\"]}>'"

URL_RE = re.compile(
    r"""(?ix)
    (?:
        git\+https://github\.com/[^\s<>"')\]}]+ |
        https?://[^\s<>"')\]}]+ |
        ssh://git@github\.com/[^\s<>"')\]}]+ |
        git@github\.com:[^\s<>"')\]}]+
    )
    """
)

OWNER_RE = r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?)"
REPO_RE = r"(?P<repo>[A-Za-z0-9._-]+?)"

GITHUB_MAIN_RE = re.compile(
    rf"(?i)^(?:git\+)?https?://(?:www\.)?github\.com/{OWNER_RE}/{REPO_RE}(?:\.git)?(?:/.*)?$"
)
GITHUB_SSH_RE = re.compile(
    rf"(?i)^(?:ssh://git@github\.com/|git@github\.com:){OWNER_RE}/{REPO_RE}(?:\.git)?(?:/.*)?$"
)
GITHUB_API_RE = re.compile(
    rf"(?i)^https?://api\.github\.com/repos/{OWNER_RE}/{REPO_RE}(?:/.*)?$"
)
GITHUB_CODELOAD_RE = re.compile(
    rf"(?i)^https?://codeload\.github\.com/{OWNER_RE}/{REPO_RE}(?:/.*)?$"
)

REJECT_GITHUB_PATTERNS = [
    re.compile(r"(?i)^https?://raw\.githubusercontent\.com/"),
    re.compile(r"(?i)^https?://gist\.github\.com/"),
    re.compile(r"(?i)^https?://github\.com/advisories(?:/|$)"),
    re.compile(r"(?i)^https?://github\.com/topics(?:/|$)"),
    re.compile(r"(?i)^https?://github\.com/marketplace(?:/|$)"),
    re.compile(r"(?i)^https?://github\.com/collections(?:/|$)"),
    re.compile(r"(?i)^https?://github\.com/explore(?:/|$)"),
    re.compile(r"(?i)^https?://[A-Za-z0-9-]+\.github\.io(?:/|$)"),
]

COMMIT_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.I)
RELEASE_TAG_RE = re.compile(r"/releases/tag/([^/\s\"'<>#?]+)", re.I)
TREE_TAG_RE = re.compile(r"/tree/([^/\s\"'<>#?]+)", re.I)
COMPARE_RE = re.compile(r"/compare/([^/\s\"'<>#?]+)", re.I)
PULL_RE = re.compile(r"/pull/(\d+)", re.I)
ISSUE_RE = re.compile(r"/issues/(\d+)", re.I)


# ------------------------------------------------------------
# Data classes
# ------------------------------------------------------------

@dataclass(frozen=True)
class GitHubRepoCandidate:
    owner: str
    repo: str
    url: str
    source: str  # ref / cpe / description
    source_json: str = ""

    @property
    def repo_key(self) -> str:
        return repo_key(self.owner, self.repo)


@dataclass(frozen=True)
class Key:
    raw: str
    norm: str
    tokens_raw: Tuple[str, ...]
    tokens_unique: Tuple[str, ...]
    token_counter: Tuple[Tuple[str, int], ...]
    compact_original: str
    compact_sorted: str


@dataclass
class AxisScore:
    score: float
    raw_score: float
    ld_sim: float
    cosine: float
    length_ratio: float
    norm_exact: bool
    token_order_exact: bool
    token_set_equal: bool
    token_len_equal: bool
    generic_removed: int
    branch: str
    left_tokens: str
    right_tokens: str
    left_compact: str
    right_compact: str


@dataclass
class CandidateScore:
    cve_id: str
    github_url: str
    source: str
    repo_key: str
    owner: str
    repo: str
    vendor: str
    product: str
    cpe_uri: str
    range_key: str
    owner_score: float
    repo_score: float
    owner_raw: float
    repo_raw: float
    fitness_score: float
    owner_branch: str
    repo_branch: str
    owner_ld: float
    owner_cosine: float
    repo_ld: float
    repo_cosine: float
    owner_generic_removed: int
    repo_generic_removed: int
    owner_penalty: float
    repo_penalty: float
    soft_tokens: str
    hard_tokens: str
    generic_tokens: str
    decision: str
    reject_reason: str


# ------------------------------------------------------------
# Generic helpers
# ------------------------------------------------------------

def qi(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, default=str, sort_keys=True)
    except Exception:
        return str(obj)


def norm_piece(s: Any) -> str:
    if s is None:
        return ""
    x = str(s).strip().lower()
    x = x.replace(".git", "")
    x = x.strip("/@")
    return x


def repo_key(owner: Any, repo: Any) -> str:
    owner = norm_piece(owner)
    repo = norm_piece(repo)
    if not owner or not repo:
        return ""
    return f"{owner}@{repo}"


def norm_repo_key(s: Any) -> str:
    if s is None:
        return ""
    x = str(s).strip().lower()
    x = x.replace("/", "@")
    x = x.replace(".git", "")
    x = x.strip("/@")
    return x


def split_repo_key(rk: str) -> Tuple[str, str]:
    rk = norm_repo_key(rk)
    if "@" not in rk:
        return "", rk
    owner, repo = rk.split("@", 1)
    return owner, repo


def strip_url(url: str) -> str:
    url = str(url or "").strip()
    while url and url[-1] in TRAILING_PUNCT:
        url = url[:-1]
    return url


def is_rejected_github_url(url: str) -> bool:
    return any(p.search(url) for p in REJECT_GITHUB_PATTERNS)


def parse_github_repo_url(url: str) -> Optional[Tuple[str, str]]:
    url = strip_url(url)
    if not url or is_rejected_github_url(url):
        return None

    for pat in (GITHUB_API_RE, GITHUB_CODELOAD_RE, GITHUB_SSH_RE, GITHUB_MAIN_RE):
        m = pat.match(url)
        if not m:
            continue

        owner = m.group("owner")
        repo = re.sub(r"(?i)\.git$", "", m.group("repo"))

        if owner.lower() in {
            "advisories", "topics", "marketplace", "collections", "explore",
            "features", "security", "settings", "orgs", "login",
        }:
            return None
        if repo.startswith("ghsa-") or repo in {".", ".."} or not repo:
            return None
        return owner, repo

    return None


def find_raw_urls(text: str) -> List[str]:
    if not text:
        return []
    return [strip_url(m.group(0)) for m in URL_RE.finditer(text)]


def classify_github_url(url: str) -> Tuple[str, Optional[str], Optional[str]]:
    if not url:
        return "github_url", None, None

    m = COMMIT_RE.search(url)
    if m:
        return "commit", m.group(1), None

    m = RELEASE_TAG_RE.search(url)
    if m:
        return "release_tag", None, m.group(1)

    m = TREE_TAG_RE.search(url)
    if m:
        return "tree", None, m.group(1)

    if COMPARE_RE.search(url):
        return "compare", None, None
    if PULL_RE.search(url):
        return "pull", None, None
    if ISSUE_RE.search(url):
        return "issue", None, None

    return "repo_or_file", None, None



# ------------------------------------------------------------
# Git sample allowlist parsing
# ------------------------------------------------------------

def parse_git_sample_line(line: str) -> Set[str]:
    """
    sample_*_git 계열 파일에서 repo_key를 추출한다.
    지원 형식:
      - owner@repo
      - owner/repo
      - https://github.com/owner/repo[/...]
      - git@github.com:owner/repo.git
      - JSON line: repo_key/git_key/repository/repo/github_repo 또는 owner+repo 필드
    """
    repos: Set[str] = set()
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return repos

    if line.startswith("{"):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                for k in ["repo_key", "git_key", "repository", "github_repo", "github", "url"]:
                    v = obj.get(k)
                    if isinstance(v, str):
                        for raw_url in find_raw_urls(v):
                            parsed = parse_github_repo_url(raw_url)
                            if parsed:
                                repos.add(repo_key(parsed[0], parsed[1]))
                        vv = v.strip().replace(".git", "")
                        if OWNER_REPO_AT_RE.fullmatch(vv) or OWNER_REPO_SLASH_RE.fullmatch(vv):
                            repos.add(norm_repo_key(vv))

                owner = obj.get("owner") or obj.get("repo_owner") or obj.get("org")
                repo = obj.get("repo") or obj.get("repo_name") or obj.get("name")
                if owner and repo:
                    rk = repo_key(owner, repo)
                    if rk:
                        repos.add(rk)
        except Exception:
            pass

    for raw_url in find_raw_urls(line):
        parsed = parse_github_repo_url(raw_url)
        if parsed:
            repos.add(repo_key(parsed[0], parsed[1]))

    for token in re.split(r"[\s,;\t]+", line):
        token = token.strip().strip("\"'`").replace(".git", "")
        if OWNER_REPO_AT_RE.fullmatch(token) or OWNER_REPO_SLASH_RE.fullmatch(token):
            repos.add(norm_repo_key(token))

    return {rk for rk in repos if rk and "@" in rk}


def iter_git_sample_files(git_dir: Optional[Path], git_lists: Sequence[Path]) -> Iterator[Path]:
    seen: Set[Path] = set()

    if git_dir:
        for p in git_dir.rglob("*"):
            if not p.is_file():
                continue
            if p.name.startswith("._"):
                continue
            if p in seen:
                continue
            seen.add(p)
            yield p

    for p in git_lists:
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"git sample list not found: {p}")
        if p in seen:
            continue
        seen.add(p)
        yield p


def load_git_sample_allowlist(git_dir: Optional[Path], git_lists: Sequence[Path]) -> Dict[str, Set[str]]:
    repo_sources: Dict[str, Set[str]] = defaultdict(set)

    for p in iter_git_sample_files(git_dir, git_lists):
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for rk in parse_git_sample_line(line):
                        repo_sources[rk].add(str(p))
        except Exception as e:
            print(f"[WARN] failed to read git sample list {p}: {e}", file=sys.stderr)
            continue

    return repo_sources


# ------------------------------------------------------------
# Similarity scoring
# ------------------------------------------------------------

def normalize_for_match(s: Any) -> str:
    s = unicodedata.normalize("NFKC", str(s or ""))
    s = s.lower().strip()
    s = re.sub(r"(?i)\.git$", "", s)
    s = s.replace("&", " and ")
    s = re.sub(r"[^a-z0-9]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def make_key(s: Any, drop_generic: bool = False) -> Key:
    norm = normalize_for_match(s)
    tokens = tuple(re.findall(r"[a-z0-9]+", norm))
    if drop_generic:
        tokens = tuple(t for t in tokens if t not in GENERIC_LOW_WEIGHT_TOKENS)

    seen: Set[str] = set()
    unique_ordered: List[str] = []
    for t in tokens:
        if t not in seen:
            unique_ordered.append(t)
            seen.add(t)

    counter = Counter(tokens)
    return Key(
        raw=str(s or ""),
        norm=" ".join(tokens),
        tokens_raw=tokens,
        tokens_unique=tuple(unique_ordered),
        token_counter=tuple(sorted(counter.items())),
        compact_original="".join(unique_ordered),
        compact_sorted="".join(sorted(unique_ordered)),
    )


def compact_of(k: Key, compact_mode: str) -> str:
    if compact_mode == "original":
        return k.compact_original
    # sorted mode is default. both_max is handled in compute_compact_scores.
    return k.compact_sorted


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            cur.append(min(ins, dele, sub))
        prev = cur
    return prev[-1]


def normalized_levenshtein_similarity(a: str, b: str) -> float:
    denom = max(len(a), len(b))
    if denom == 0:
        return 0.0
    return 1.0 - (levenshtein_distance(a, b) / denom)


def char_ngrams(s: str, n: int) -> Counter:
    if not s:
        return Counter()
    if len(s) < n:
        return Counter([s])
    return Counter(s[i:i + n] for i in range(len(s) - n + 1))


def cosine_counter(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b[k] for k in (set(a) & set(b)))
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def char_ngram_cosine(a: str, b: str, n: int = 2) -> float:
    return cosine_counter(char_ngrams(a, n), char_ngrams(b, n))


def length_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    mx = max(len(a), len(b))
    mn = min(len(a), len(b))
    if mx == 0:
        return 0.0
    return mn / mx


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def alpha_mix(ld_sim: float, cosine: float, alpha: float) -> float:
    return alpha * ld_sim + (1.0 - alpha) * cosine


def compute_compact_scores(left: Key, right: Key, ngram: int, compact_mode: str) -> Tuple[float, float, float, str, str]:
    if compact_mode == "both_max":
        pairs = [
            (left.compact_original, right.compact_original),
            (left.compact_sorted, right.compact_sorted),
        ]
        best = None
        for a, b in pairs:
            ld = normalized_levenshtein_similarity(a, b)
            cos = char_ngram_cosine(a, b, ngram)
            lr = length_ratio(a, b)
            score = ld + cos + lr
            if best is None or score > best[0]:
                best = (score, ld, cos, lr, a, b)
        assert best is not None
        return best[1], best[2], best[3], best[4], best[5]

    a = compact_of(left, compact_mode)
    b = compact_of(right, compact_mode)
    return (
        normalized_levenshtein_similarity(a, b),
        char_ngram_cosine(a, b, ngram),
        length_ratio(a, b),
        a,
        b,
    )


def score_equal_or_raw(left: Key, right: Key, alpha: float, ngram: int, compact_mode: str) -> AxisScore:
    ld, cos, lr, left_compact, right_compact = compute_compact_scores(left, right, ngram, compact_mode)
    raw = alpha_mix(ld, cos, alpha)

    norm_exact = bool(left.norm and left.norm == right.norm)
    token_order_exact = bool(left.tokens_unique and left.tokens_unique == right.tokens_unique)
    token_set_equal = bool(left.tokens_unique and set(left.tokens_unique) == set(right.tokens_unique))
    token_len_equal = bool(left.tokens_unique and len(left.tokens_unique) == len(right.tokens_unique))

    if norm_exact or token_order_exact:
        score = 1.0
        branch = "exact"
    elif token_set_equal:
        score = max(raw, 0.95)
        branch = "token_set_equal"
    else:
        score = raw
        branch = "char_score"

    return AxisScore(
        score=clamp01(score),
        raw_score=clamp01(raw),
        ld_sim=ld,
        cosine=cos,
        length_ratio=lr,
        norm_exact=norm_exact,
        token_order_exact=token_order_exact,
        token_set_equal=token_set_equal,
        token_len_equal=token_len_equal,
        generic_removed=0,
        branch=branch,
        left_tokens=" ".join(left.tokens_unique),
        right_tokens=" ".join(right.tokens_unique),
        left_compact=left_compact,
        right_compact=right_compact,
    )


def count_removed_generic(original: Key, filtered: Key) -> int:
    return max(0, len(original.tokens_unique) - len(filtered.tokens_unique))


def score_axis(left_raw: Any, right_raw: Any, alpha: float, ngram: int, compact_mode: str) -> AxisScore:
    """
    left_raw/right_raw 한 축의 score를 계산한다.
    - token 길이가 같으면 바로 token/char score 계산
    - token 길이가 다르면 generic low-weight token 제거 후 재비교
    - 제거 후 같아지면 generic penalty만 차감
    - 제거 후에도 다르면 raw char score를 사용하되 cap은 적용하지 않는다.
    """
    left = make_key(left_raw)
    right = make_key(right_raw)

    if len(left.tokens_unique) == len(right.tokens_unique):
        out = score_equal_or_raw(left, right, alpha, ngram, compact_mode)
        out.branch = "equal_len:" + out.branch
        return out

    left_g = make_key(left_raw, drop_generic=True)
    right_g = make_key(right_raw, drop_generic=True)
    removed = count_removed_generic(left, left_g) + count_removed_generic(right, right_g)

    if len(left_g.tokens_unique) == len(right_g.tokens_unique) and len(left_g.tokens_unique) > 0:
        out = score_equal_or_raw(left_g, right_g, alpha, ngram, compact_mode)
        out.generic_removed = removed
        out.score = clamp01(out.score - 0.03 * removed)
        out.branch = "generic_removed_equal_len:" + out.branch
        return out

    out = score_equal_or_raw(left, right, alpha, ngram, compact_mode)
    out.generic_removed = removed
    if removed:
        out.score = clamp01(out.score - 0.03 * removed)
    out.branch = "unequal_len:" + out.branch
    return out


def tokens_anywhere(*seqs: Sequence[str]) -> Set[str]:
    out: Set[str] = set()
    for seq in seqs:
        out.update(seq)
    return out


def token_class_counts(tokens: Sequence[str]) -> Tuple[Set[str], Set[str], Set[str]]:
    toks = set(tokens)
    generic = toks & GENERIC_LOW_WEIGHT_TOKENS
    soft = toks & SOFT_NON_PRODUCT_TOKENS
    hard = toks & HARD_NON_PRODUCT_TOKENS
    return generic, soft, hard


def non_product_penalty(tokens: Sequence[str]) -> float:
    generic, soft, hard = token_class_counts(tokens)
    penalty = 0.0
    if generic:
        penalty += 0.03 * len(generic)
    if soft:
        penalty += 0.15 * len(soft)
    if hard:
        penalty += 0.35 * len(hard)
    return min(penalty, 0.50)


def score_candidate(
    cve_id: str,
    cpe_row: Dict[str, Any],
    gh: GitHubRepoCandidate,
    alpha_owner: float,
    alpha_repo: float,
    owner_weight: float,
    threshold: float,
    ngram: int,
    compact_mode: str,
    reject_soft_hard: bool = True,
) -> CandidateScore:
    vendor = cpe_row.get("vendor") or ""
    product = cpe_row.get("product") or ""
    owner = gh.owner
    repo = gh.repo

    owner_axis = score_axis(vendor, owner, alpha_owner, ngram, compact_mode)
    repo_axis = score_axis(product, repo, alpha_repo, ngram, compact_mode)

    owner_key = make_key(owner)
    repo_key_obj = make_key(repo)
    vendor_key = make_key(vendor)
    product_key = make_key(product)

    owner_pen = non_product_penalty(owner_key.tokens_unique)
    repo_pen = non_product_penalty(repo_key_obj.tokens_unique)

    owner_score = clamp01(owner_axis.score - owner_pen)
    repo_score = clamp01(repo_axis.score - repo_pen)
    fitness = clamp01(owner_weight * owner_score + (1.0 - owner_weight) * repo_score)

    all_tokens = tokens_anywhere(owner_key.tokens_unique, repo_key_obj.tokens_unique)
    generic, soft, hard = token_class_counts(tuple(all_tokens))

    if reject_soft_hard and (soft or hard):
        decision = "reject"
        reject_reason = "soft_or_hard_non_product_token"
    elif fitness >= threshold:
        decision = "accept"
        reject_reason = ""
    else:
        decision = "reject"
        reject_reason = "below_threshold"

    range_key = "|".join([
        str(cpe_row.get("cpe_uri") or ""),
        str(cpe_row.get("version_start_including") or ""),
        str(cpe_row.get("version_start_excluding") or ""),
        str(cpe_row.get("version_end_including") or ""),
        str(cpe_row.get("version_end_excluding") or ""),
    ])

    return CandidateScore(
        cve_id=cve_id,
        github_url=gh.url,
        source=gh.source,
        repo_key=gh.repo_key,
        owner=owner,
        repo=repo,
        vendor=str(vendor),
        product=str(product),
        cpe_uri=str(cpe_row.get("cpe_uri") or ""),
        range_key=range_key,
        owner_score=owner_score,
        repo_score=repo_score,
        owner_raw=owner_axis.raw_score,
        repo_raw=repo_axis.raw_score,
        fitness_score=fitness,
        owner_branch=owner_axis.branch,
        repo_branch=repo_axis.branch,
        owner_ld=owner_axis.ld_sim,
        owner_cosine=owner_axis.cosine,
        repo_ld=repo_axis.ld_sim,
        repo_cosine=repo_axis.cosine,
        owner_generic_removed=owner_axis.generic_removed,
        repo_generic_removed=repo_axis.generic_removed,
        owner_penalty=owner_pen,
        repo_penalty=repo_pen,
        soft_tokens=" ".join(sorted(soft)),
        hard_tokens=" ".join(sorted(hard)),
        generic_tokens=" ".join(sorted(generic)),
        decision=decision,
        reject_reason=reject_reason,
    )


# ------------------------------------------------------------
# CPE parsing / NVD extraction
# ------------------------------------------------------------

def split_cpe23(cpe_uri: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    esc = False
    for ch in str(cpe_uri or ""):
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == ":":
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return parts


def parse_cpe_uri(cpe_uri: Any) -> Dict[str, Optional[str]]:
    cpe_uri = str(cpe_uri or "")
    result = {"part": None, "vendor": None, "product": None, "version": None}
    if not cpe_uri.startswith("cpe:2.3:"):
        return result
    parts = split_cpe23(cpe_uri)
    if len(parts) >= 6:
        result["part"] = parts[2]
        result["vendor"] = cpe_unescape(parts[3])
        result["product"] = cpe_unescape(parts[4])
        result["version"] = cpe_unescape(parts[5])
    return result


def cpe_unescape(s: Any) -> str:
    s = str(s or "")
    s = s.replace(r"\:", ":")
    s = s.replace(r"\_", "_")
    s = s.replace(r"\-", "-")
    s = s.replace(r"\.", ".")
    s = s.replace(r"\/", "/")
    return s


def iter_cpe_matches_from_node(node: Any) -> Iterator[Dict[str, Any]]:
    if not isinstance(node, dict):
        return

    for key in ["cpeMatch", "cpe_match"]:
        items = node.get(key)
        if isinstance(items, list):
            for m in items:
                if isinstance(m, dict):
                    yield m

    for key in ["nodes", "children"]:
        children = node.get(key)
        if isinstance(children, list):
            for child in children:
                yield from iter_cpe_matches_from_node(child)


def iter_cpe_matches_from_configurations(configurations: Any) -> Iterator[Dict[str, Any]]:
    if configurations is None:
        return
    if isinstance(configurations, dict):
        for node in configurations.get("nodes", []):
            yield from iter_cpe_matches_from_node(node)
        return
    if isinstance(configurations, list):
        for cfg in configurations:
            if not isinstance(cfg, dict):
                continue
            for node in cfg.get("nodes", []):
                yield from iter_cpe_matches_from_node(node)
        return


def cpe_range_has_version_info(row: Dict[str, Any]) -> bool:
    exact = str(row.get("cpe_version") or "").strip().lower()
    if exact not in WILDCARD_VERSIONS:
        return True
    return any(
        str(row.get(k) or "").strip()
        for k in (
            "version_start_including", "version_start_excluding",
            "version_end_including", "version_end_excluding",
        )
    )


def iter_strings(obj: Any) -> Iterator[str]:
    if obj is None:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_strings(v)


def collect_text(obj: Any) -> str:
    return "\n".join(s for s in iter_strings(obj) if s)


def extract_cve_id(cve: Dict[str, Any], raw: Dict[str, Any]) -> Optional[str]:
    candidates = [
        cve.get("id"),
        cve.get("CVE_data_meta", {}).get("ID") if isinstance(cve.get("CVE_data_meta"), dict) else None,
        raw.get("cve_id"),
        raw.get("id"),
    ]
    for v in candidates:
        if isinstance(v, str) and CVE_RE.fullmatch(v.strip()):
            return v.strip().upper()
    m = CVE_RE.search(safe_json(raw))
    return m.group(0).upper() if m else None


def extract_description(cve: Dict[str, Any]) -> str:
    descs = cve.get("descriptions")
    if isinstance(descs, list):
        for d in descs:
            if isinstance(d, dict) and d.get("lang") == "en":
                return str(d.get("value") or "")
        for d in descs:
            if isinstance(d, dict) and d.get("value"):
                return str(d.get("value") or "")

    legacy = cve.get("description")
    if isinstance(legacy, dict):
        data = legacy.get("description_data")
        if isinstance(data, list):
            for d in data:
                if isinstance(d, dict) and d.get("lang") == "en":
                    return str(d.get("value") or "")
            for d in data:
                if isinstance(d, dict) and d.get("value"):
                    return str(d.get("value") or "")
    if isinstance(legacy, str):
        return legacy
    return ""


def extract_references(cve: Dict[str, Any], raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = cve.get("references")
    if isinstance(refs, list):
        return [r for r in refs if isinstance(r, dict)]
    if isinstance(refs, dict) and isinstance(refs.get("reference_data"), list):
        return [r for r in refs["reference_data"] if isinstance(r, dict)]
    refs = raw.get("references")
    if isinstance(refs, list):
        return [r for r in refs if isinstance(r, dict)]
    return []


def extract_configurations(cve: Dict[str, Any], raw: Dict[str, Any]) -> Any:
    if "configurations" in cve:
        return cve.get("configurations")
    if "configurations" in raw:
        return raw.get("configurations")
    return None


def has_cvss(cve: Dict[str, Any], raw: Dict[str, Any]) -> bool:
    for root in [cve.get("metrics"), raw.get("metrics"), raw.get("impact")]:
        if isinstance(root, dict) and root:
            text = safe_json(root).lower()
            if "cvss" in text or "basescore" in text or "baseseverity" in text:
                return True
    return False


def make_cpe_range_rows(cve_id: str, cve: Dict[str, Any], raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Set[Tuple[Any, ...]] = set()

    configurations = extract_configurations(cve, raw)
    for m in iter_cpe_matches_from_configurations(configurations):
        vulnerable = m.get("vulnerable")
        if vulnerable is False:
            continue
        cpe_uri = m.get("criteria") or m.get("cpe23Uri") or m.get("cpe23uri")
        parsed = parse_cpe_uri(cpe_uri)
        row = {
            "cve_id": cve_id,
            "cpe_uri": cpe_uri,
            "part": parsed.get("part"),
            "vendor": parsed.get("vendor"),
            "product": parsed.get("product"),
            "cpe_version": parsed.get("version"),
            "version_start_including": m.get("versionStartIncluding") or m.get("version_start_including"),
            "version_start_excluding": m.get("versionStartExcluding") or m.get("version_start_excluding"),
            "version_end_including": m.get("versionEndIncluding") or m.get("version_end_including"),
            "version_end_excluding": m.get("versionEndExcluding") or m.get("version_end_excluding"),
            "vulnerable": 1 if vulnerable is not False else 0,
            "match_criteria_id": m.get("matchCriteriaId") or m.get("match_criteria_id"),
            "raw_json": safe_json(m),
        }
        key = (
            row["cpe_uri"], row["version_start_including"], row["version_start_excluding"],
            row["version_end_including"], row["version_end_excluding"], row["match_criteria_id"],
        )
        if key in seen:
            continue
        seen.add(key)
        if row.get("vendor") and row.get("product"):
            rows.append(row)

    return rows


def get_reference_text_and_sources(refs: List[Dict[str, Any]]) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    parts: List[str] = []
    by_url: Dict[str, Dict[str, Any]] = {}
    for ref in refs:
        url = str(ref.get("url") or ref.get("href") or "")
        if url:
            parts.append(url)
            by_url[strip_url(url)] = ref
        else:
            parts.extend(iter_strings(ref))
    return "\n".join(parts), by_url


def get_cpe_text(cve: Dict[str, Any], raw: Dict[str, Any]) -> str:
    roots = [
        extract_configurations(cve, raw),
        raw.get("cpe"), raw.get("cpes"), raw.get("cpe_matches"), raw.get("version_evidence"), raw.get("nvd_products"),
    ]
    return "\n".join(collect_text(r) for r in roots if r is not None)


def extract_github_repos_from_text(
    text: str,
    source: str,
    stats: Counter,
    source_json_by_url: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[GitHubRepoCandidate]:
    repos: List[GitHubRepoCandidate] = []
    seen: Set[Tuple[str, str, str]] = set()

    for url in find_raw_urls(text):
        if "github" not in url.lower():
            continue
        if is_rejected_github_url(url):
            stats[f"github_rejected_url_{source}"] += 1
            continue
        parsed = parse_github_repo_url(url)
        if parsed is None:
            stats[f"github_unaccepted_url_{source}"] += 1
            continue
        owner, repo = parsed
        key = (owner.lower(), repo.lower(), source)
        if key in seen:
            continue
        seen.add(key)
        src_obj = source_json_by_url.get(strip_url(url), {}) if source_json_by_url else {}
        repos.append(GitHubRepoCandidate(owner=owner, repo=repo, url=url, source=source, source_json=safe_json(src_obj)))
        stats[f"github_accepted_url_{source}"] += 1
    return repos


def extract_github_repos_by_priority(cve: Dict[str, Any], raw: Dict[str, Any], stats: Counter) -> List[GitHubRepoCandidate]:
    refs = extract_references(cve, raw)
    ref_text, ref_by_url = get_reference_text_and_sources(refs)
    source_texts = [
        ("ref", ref_text, ref_by_url),
        ("cpe", get_cpe_text(cve, raw), None),
        ("description", extract_description(cve), None),
    ]
    for source, text, by_url in source_texts:
        repos = extract_github_repos_from_text(text, source, stats, by_url)
        if repos:
            stats[f"github_selected_source_{source}"] += 1
            return repos
    stats["github_not_found"] += 1
    return []


# ------------------------------------------------------------
# NVD input parsing
# ------------------------------------------------------------

def open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def load_json_or_jsonl(path: Path) -> Iterable[Any]:
    with open_text(path) as f:
        prefix = f.read(4096)
        f.seek(0)
        stripped = prefix.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                yield json.load(f)
                return
            except Exception:
                f.seek(0)

        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line in {"[", "]"}:
                continue
            if line.endswith(","):
                line = line[:-1].rstrip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as e:
                print(f"[WARN] skip malformed JSON line {path}:{line_no}: {e}", file=sys.stderr)
                continue


def find_nvd_files(nvd_input: Path) -> List[Path]:
    if nvd_input.is_file():
        return [nvd_input]
    files: List[Path] = []
    for p in nvd_input.rglob("*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")):
            files.append(p)
    return sorted(files)


def iter_nvd_records(nvd_input: Path) -> Iterator[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for path in find_nvd_files(nvd_input):
        print(f"[NVD] reading {path}", file=sys.stderr)
        for obj in load_json_or_jsonl(path):
            if isinstance(obj, dict) and isinstance(obj.get("vulnerabilities"), list):
                for item in obj["vulnerabilities"]:
                    if isinstance(item, dict) and isinstance(item.get("cve"), dict):
                        yield item["cve"], item
                continue
            if isinstance(obj, dict) and isinstance(obj.get("CVE_Items"), list):
                for item in obj["CVE_Items"]:
                    if isinstance(item, dict) and isinstance(item.get("cve"), dict):
                        yield item["cve"], item
                continue
            if isinstance(obj, list):
                for item in obj:
                    if not isinstance(item, dict):
                        continue
                    if isinstance(item.get("cve"), dict):
                        yield item["cve"], item
                    elif CVE_RE.search(safe_json(item)):
                        yield item, item
                continue
            if isinstance(obj, dict):
                if isinstance(obj.get("cve"), dict):
                    yield obj["cve"], obj
                elif CVE_RE.search(safe_json(obj)):
                    yield obj, obj


# ------------------------------------------------------------
# Version normalization / comparison
# ------------------------------------------------------------

def normalize_version_string(s: Any) -> str:
    if s is None:
        return ""
    raw = str(s).strip()
    if not raw:
        return ""
    x = raw.replace("refs/tags/", "").strip()
    x = re.sub(r"^(release|rel|version|ver|tag|v)[\-_./ ]*", "", x, flags=re.I)
    m = re.search(r"(\d+(?:[._-]\d+)*(?:[a-zA-Z][0-9]*)?)", x)
    if m:
        x = m.group(1)
    x = x.replace("_", ".").replace("-", ".")
    x = re.sub(r"\.+", ".", x).strip(".")
    return x.lower()


def version_tokens(s: Any) -> List[Any]:
    ns = normalize_version_string(s)
    if not ns:
        return []
    parts = re.findall(r"\d+|[a-zA-Z]+", ns)
    out: List[Any] = []
    for p in parts:
        out.append(int(p) if p.isdigit() else p.lower())
    return out


def cmp_version(a: Any, b: Any) -> Optional[int]:
    ta = version_tokens(a)
    tb = version_tokens(b)
    if not ta or not tb:
        return None
    n = max(len(ta), len(tb))
    for i in range(n):
        va = ta[i] if i < len(ta) else 0
        vb = tb[i] if i < len(tb) else 0
        if va == vb:
            continue
        if isinstance(va, int) and isinstance(vb, int):
            return -1 if va < vb else 1
        if isinstance(va, int) and isinstance(vb, str):
            return -1 if va == 0 else 1
        if isinstance(va, str) and isinstance(vb, int):
            return 1 if vb == 0 else -1
        return -1 if str(va) < str(vb) else 1
    return 0


def version_matches_range(version_raw: str, rng: Dict[str, Any]) -> Tuple[bool, str]:
    candidate = normalize_version_string(version_raw)
    if not candidate:
        return False, "skip_empty_candidate_version"

    exact = rng.get("cpe_version")
    start_inc = rng.get("version_start_including")
    start_exc = rng.get("version_start_excluding")
    end_inc = rng.get("version_end_including")
    end_exc = rng.get("version_end_excluding")
    has_range = any(x not in (None, "", "null") for x in [start_inc, start_exc, end_inc, end_exc])

    if exact is not None and str(exact).strip().lower() not in WILDCARD_VERSIONS and not has_range:
        c = cmp_version(candidate, exact)
        if c is not None and c == 0:
            return True, "exact_cpe_version_match"
        if normalize_version_string(candidate) == normalize_version_string(exact):
            return True, "exact_cpe_version_string_match"
        return False, "not_exact_cpe_version"

    if not has_range:
        return False, "skip_no_usable_range"

    if start_inc not in (None, "", "null"):
        c = cmp_version(candidate, start_inc)
        if c is None:
            return False, "skip_uncomparable_start_including"
        if c < 0:
            return False, "below_start_including"
    if start_exc not in (None, "", "null"):
        c = cmp_version(candidate, start_exc)
        if c is None:
            return False, "skip_uncomparable_start_excluding"
        if c <= 0:
            return False, "below_or_equal_start_excluding"
    if end_inc not in (None, "", "null"):
        c = cmp_version(candidate, end_inc)
        if c is None:
            return False, "skip_uncomparable_end_including"
        if c > 0:
            return False, "above_end_including"
    if end_exc not in (None, "", "null"):
        c = cmp_version(candidate, end_exc)
        if c is None:
            return False, "skip_uncomparable_end_excluding"
        if c >= 0:
            return False, "above_or_equal_end_excluding"

    return True, "range_match"


# ------------------------------------------------------------
# GitHub cache parsing
# ------------------------------------------------------------

def load_cache_json(path: Path) -> Iterable[Any]:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
                yield json.load(f)
        else:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
                stripped = text.lstrip()
                if stripped.startswith("{") or stripped.startswith("["):
                    yield json.loads(text)
                else:
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.endswith(","):
                            line = line[:-1].rstrip()
                        try:
                            yield json.loads(line)
                        except Exception:
                            continue
    except Exception:
        return


def infer_repo_key_from_path(path: Path) -> Optional[str]:
    text = str(path)
    m = re.search(r"([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)", text)
    if m:
        return repo_key(m.group(1), m.group(2))
    m = re.search(r"([A-Za-z0-9_.-]+)__([A-Za-z0-9_.-]+)", text)
    if m:
        return repo_key(m.group(1), m.group(2))
    return None


def infer_repo_key_from_obj(obj: Any) -> Optional[str]:
    text = safe_json(obj)
    repos = []
    for url in find_raw_urls(text):
        parsed = parse_github_repo_url(url)
        if parsed:
            repos.append(repo_key(parsed[0], parsed[1]))
    repos = sorted(set(repos))
    if len(repos) == 1:
        return repos[0]

    if isinstance(obj, dict):
        for key in ["repo_key", "git_key"]:
            if isinstance(obj.get(key), str):
                return norm_repo_key(obj[key])
        full_name = obj.get("full_name")
        if isinstance(full_name, str) and "/" in full_name:
            return norm_repo_key(full_name)
        repo = obj.get("repository")
        if isinstance(repo, dict):
            full_name = repo.get("full_name")
            if isinstance(full_name, str) and "/" in full_name:
                return norm_repo_key(full_name)
    return None


def unwrap_cache_payload(obj: Any) -> List[Any]:
    if isinstance(obj, list):
        return obj
    if not isinstance(obj, dict):
        return []
    for key in ["data", "items", "result", "response"]:
        if isinstance(obj.get(key), list):
            return obj[key]
    combined: List[Any] = []
    for key in ["tags", "releases", "commits"]:
        if isinstance(obj.get(key), list):
            combined.extend(obj[key])
    if combined:
        return combined
    return [obj]


def classify_cache_item(item: Dict[str, Any], path: Path) -> Optional[str]:
    name = path.name.lower()
    if "release" in name or "releases" in name:
        if "tag_name" in item or "name" in item:
            return "release"
    if "tag" in name or "tags" in name:
        if "name" in item:
            return "tag"
    if "commit" in name or "commits" in name:
        if "sha" in item:
            return "commit"
    if "tag_name" in item:
        return "release"
    if "sha" in item and isinstance(item.get("commit"), dict):
        return "commit"
    if "name" in item and isinstance(item.get("commit"), dict):
        return "tag"
    if "name" in item and "zipball_url" in item:
        return "release"
    return None


def extract_version_from_cache_item(repo: str, kind: str, item: Dict[str, Any], path: Path) -> Optional[Dict[str, Any]]:
    if kind == "release":
        version_raw = item.get("tag_name") or item.get("name")
        if not version_raw:
            return None
        return {
            "repo_key": repo,
            "version_raw": str(version_raw),
            "version_norm": normalize_version_string(version_raw),
            "source": "release",
            "commit_sha": item.get("target_commitish"),
            "published_at": item.get("published_at"),
            "created_at": item.get("created_at"),
            "cache_file": str(path),
            "raw_json": safe_json(item),
        }
    if kind == "tag":
        version_raw = item.get("name")
        if not version_raw:
            return None
        commit_sha = None
        commit = item.get("commit")
        if isinstance(commit, dict):
            commit_sha = commit.get("sha")
        return {
            "repo_key": repo,
            "version_raw": str(version_raw),
            "version_norm": normalize_version_string(version_raw),
            "source": "tag",
            "commit_sha": commit_sha,
            "published_at": None,
            "created_at": None,
            "cache_file": str(path),
            "raw_json": safe_json(item),
        }
    return None


def extract_commit_from_cache_item(repo: str, item: Dict[str, Any], path: Path) -> Optional[Dict[str, Any]]:
    sha = item.get("sha")
    if not sha:
        return None
    commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
    message = commit.get("message")
    date = None
    committer = commit.get("committer")
    author = commit.get("author")
    if isinstance(committer, dict):
        date = committer.get("date")
    if not date and isinstance(author, dict):
        date = author.get("date")
    return {
        "repo_key": repo,
        "commit_sha": sha,
        "commit_date": date,
        "message": message,
        "cache_file": str(path),
        "raw_json": safe_json(item),
    }


def iter_cache_files(cache_dir: Path) -> Iterator[Path]:
    if not cache_dir.exists():
        return
    for p in cache_dir.rglob("*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")):
            yield p


# ------------------------------------------------------------
# DB setup: same schema as 02-01
# ------------------------------------------------------------

def connect_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def setup_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = OFF;
        PRAGMA temp_store = MEMORY;

        CREATE TABLE IF NOT EXISTS repositories (
            repo_key TEXT PRIMARY KEY,
            owner TEXT,
            repo TEXT,
            has_github_cache INTEGER DEFAULT 0,
            cache_files_json TEXT
        );

        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            published TEXT,
            last_modified TEXT,
            vuln_status TEXT,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS cve_github_refs (
            cve_id TEXT NOT NULL,
            repo_key TEXT NOT NULL,
            github_url TEXT NOT NULL,
            ref_kind TEXT,
            commit_sha TEXT,
            tag_name TEXT,
            source TEXT,
            reference_json TEXT,
            PRIMARY KEY (cve_id, repo_key, github_url)
        );

        CREATE TABLE IF NOT EXISTS nvd_cpe_ranges (
            range_id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            cpe_uri TEXT,
            part TEXT,
            vendor TEXT,
            product TEXT,
            cpe_version TEXT,
            version_start_including TEXT,
            version_start_excluding TEXT,
            version_end_including TEXT,
            version_end_excluding TEXT,
            vulnerable INTEGER,
            match_criteria_id TEXT,
            raw_json TEXT
        );

        CREATE TABLE IF NOT EXISTS github_versions (
            repo_key TEXT NOT NULL,
            version_raw TEXT NOT NULL,
            version_norm TEXT,
            source TEXT,
            commit_sha TEXT,
            published_at TEXT,
            created_at TEXT,
            cache_file TEXT,
            raw_json TEXT
        );

        CREATE TABLE IF NOT EXISTS github_commits (
            repo_key TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            commit_date TEXT,
            message TEXT,
            cache_file TEXT,
            raw_json TEXT,
            PRIMARY KEY(repo_key, commit_sha)
        );

        CREATE TABLE IF NOT EXISTS version_cve_index (
            cve_id TEXT NOT NULL,
            repo_key TEXT NOT NULL,
            version_raw TEXT NOT NULL,
            version_norm TEXT,
            version_source TEXT,
            range_id INTEGER,
            cpe_uri TEXT,
            match_reason TEXT,
            github_refs_json TEXT,
            UNIQUE(cve_id, repo_key, version_raw, version_source, range_id)
        );

        CREATE TABLE IF NOT EXISTS build_summary (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_refs_cve ON cve_github_refs(cve_id);
        CREATE INDEX IF NOT EXISTS idx_refs_repo ON cve_github_refs(repo_key);
        CREATE INDEX IF NOT EXISTS idx_ranges_cve ON nvd_cpe_ranges(cve_id);
        CREATE INDEX IF NOT EXISTS idx_versions_repo ON github_versions(repo_key);
        CREATE INDEX IF NOT EXISTS idx_versions_repo_ver ON github_versions(repo_key, version_raw);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_github_versions_unique
          ON github_versions(repo_key, version_raw, COALESCE(source, ''), COALESCE(commit_sha, ''));
        CREATE INDEX IF NOT EXISTS idx_commits_repo ON github_commits(repo_key);
        CREATE INDEX IF NOT EXISTS idx_index_repo_version ON version_cve_index(repo_key, version_raw);
        CREATE INDEX IF NOT EXISTS idx_index_cve ON version_cve_index(cve_id);
        """
    )
    conn.commit()


def insert_repository(conn: sqlite3.Connection, rk: str) -> None:
    owner, name = split_repo_key(rk)
    conn.execute(
        """
        INSERT OR IGNORE INTO repositories(repo_key, owner, repo)
        VALUES (?, ?, ?)
        """,
        (rk, owner, name),
    )


# ------------------------------------------------------------
# Build NVD -> DB
# ------------------------------------------------------------

def reference_json_for_candidate(gh: GitHubRepoCandidate, cs: CandidateScore, cpe_row: Dict[str, Any]) -> str:
    return safe_json({
        "original_source_json": json.loads(gh.source_json) if gh.source_json else {},
        "refiltering_policy": "ref_cpe_description_priority_similarity_filter",
        "score": asdict(cs),
        "matched_cpe_range": {
            "cpe_uri": cpe_row.get("cpe_uri"),
            "vendor": cpe_row.get("vendor"),
            "product": cpe_row.get("product"),
            "cpe_version": cpe_row.get("cpe_version"),
            "version_start_including": cpe_row.get("version_start_including"),
            "version_start_excluding": cpe_row.get("version_start_excluding"),
            "version_end_including": cpe_row.get("version_end_including"),
            "version_end_excluding": cpe_row.get("version_end_excluding"),
        },
    })


def build_from_nvd(conn: sqlite3.Connection, nvd_input: Path, args: argparse.Namespace, out_dir: Path) -> Counter:
    stats = Counter()

    cve_insert = """
        INSERT OR IGNORE INTO cves
        (cve_id, published, last_modified, vuln_status, description)
        VALUES (?, ?, ?, ?, ?)
    """

    ref_insert = """
        INSERT OR REPLACE INTO cve_github_refs
        (cve_id, repo_key, github_url, ref_kind, commit_sha, tag_name, source, reference_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """

    range_insert = """
        INSERT INTO nvd_cpe_ranges
        (
            cve_id, cpe_uri, part, vendor, product, cpe_version,
            version_start_including, version_start_excluding,
            version_end_including, version_end_excluding,
            vulnerable, match_criteria_id, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    accepted_audit: List[Dict[str, Any]] = []
    rejected_audit: List[Dict[str, Any]] = []
    seen_ranges_global: Set[Tuple[Any, ...]] = set()

    for cve, raw in iter_nvd_records(nvd_input):
        stats["nvd_records"] += 1
        cve_id = extract_cve_id(cve, raw)
        if not cve_id:
            stats["skip_no_cve_id"] += 1
            continue

        cvss_present = has_cvss(cve, raw)
        cpe_rows_all = make_cpe_range_rows(cve_id, cve, raw)
        if not cpe_rows_all:
            if cvss_present:
                stats["filtered_no_cpe_cvss_only"] += 1
            else:
                stats["filtered_no_cpe_no_cvss"] += 1
            continue
        stats["records_with_cpe"] += 1

        cpe_rows = [r for r in cpe_rows_all if cpe_range_has_version_info(r)]
        if not cpe_rows:
            stats["filtered_cpe_without_version_info"] += 1
            continue
        stats["records_with_cpe_version_info"] += 1

        gh_candidates = extract_github_repos_by_priority(cve, raw, stats)
        if not gh_candidates:
            continue
        stats["records_with_github_repo"] += 1

        if args.git_allowlist:
            before_allowlist = len(gh_candidates)
            gh_candidates = [gh for gh in gh_candidates if gh.repo_key in args.git_allowlist]
            filtered = before_allowlist - len(gh_candidates)
            if filtered:
                stats["github_candidate_filtered_not_in_git_sample"] += filtered
            if not gh_candidates:
                stats["records_with_github_but_not_in_git_sample"] += 1
                continue

        best_by_ref: Dict[Tuple[str, str, str], Tuple[CandidateScore, GitHubRepoCandidate, Dict[str, Any]]] = {}
        accepted_range_keys: Set[Tuple[Any, ...]] = set()

        for cpe_row in cpe_rows:
            for gh in gh_candidates:
                stats["candidate_pairs_total"] += 1
                cs = score_candidate(
                    cve_id=cve_id,
                    cpe_row=cpe_row,
                    gh=gh,
                    alpha_owner=args.alpha_owner,
                    alpha_repo=args.alpha_repo,
                    owner_weight=args.owner_weight,
                    threshold=args.threshold,
                    ngram=args.ngram,
                    compact_mode=args.compact_mode,
                    reject_soft_hard=not args.allow_soft_hard,
                )

                if cs.decision == "accept":
                    stats["candidate_accept"] += 1
                    key = (cve_id, cs.repo_key, cs.github_url)
                    old = best_by_ref.get(key)
                    if old is None or cs.fitness_score > old[0].fitness_score:
                        best_by_ref[key] = (cs, gh, cpe_row)
                    accepted_range_keys.add((
                        cve_id,
                        cpe_row.get("cpe_uri"),
                        cpe_row.get("version_start_including"),
                        cpe_row.get("version_start_excluding"),
                        cpe_row.get("version_end_including"),
                        cpe_row.get("version_end_excluding"),
                        cpe_row.get("match_criteria_id"),
                    ))
                    if args.write_audit:
                        accepted_audit.append(asdict(cs))
                else:
                    stats[f"candidate_reject:{cs.reject_reason}"] += 1
                    if cs.soft_tokens:
                        stats["candidate_reject_has_soft_token"] += 1
                    if cs.hard_tokens:
                        stats["candidate_reject_has_hard_token"] += 1
                    if args.write_audit and len(rejected_audit) < args.max_rejected_audit_rows:
                        rejected_audit.append(asdict(cs))

        if not best_by_ref:
            stats["records_with_github_but_no_accepted_mapping"] += 1
            continue

        conn.execute(
            cve_insert,
            (
                cve_id,
                cve.get("published") or raw.get("publishedDate"),
                cve.get("lastModified") or raw.get("lastModifiedDate"),
                cve.get("vulnStatus"),
                extract_description(cve),
            ),
        )

        for (cve_id_, rk, github_url), (cs, gh, cpe_row) in best_by_ref.items():
            insert_repository(conn, rk)
            ref_kind, commit_sha, tag_name = classify_github_url(github_url)
            conn.execute(
                ref_insert,
                (
                    cve_id_,
                    rk,
                    github_url,
                    ref_kind,
                    commit_sha,
                    tag_name,
                    f"{gh.source}:score_filter",
                    reference_json_for_candidate(gh, cs, cpe_row),
                ),
            )
            stats["cve_github_refs_insert_attempt"] += 1

        # Insert CPE ranges for accepted CPE evidence only.
        for row in cpe_rows:
            range_key_tuple = (
                cve_id,
                row.get("cpe_uri"),
                row.get("version_start_including"),
                row.get("version_start_excluding"),
                row.get("version_end_including"),
                row.get("version_end_excluding"),
                row.get("match_criteria_id"),
            )
            if range_key_tuple not in accepted_range_keys:
                continue
            if range_key_tuple in seen_ranges_global:
                continue
            seen_ranges_global.add(range_key_tuple)

            conn.execute(
                range_insert,
                (
                    row["cve_id"], row["cpe_uri"], row["part"], row["vendor"], row["product"], row["cpe_version"],
                    row["version_start_including"], row["version_start_excluding"],
                    row["version_end_including"], row["version_end_excluding"],
                    row["vulnerable"], row["match_criteria_id"], row["raw_json"],
                ),
            )
            stats["nvd_cpe_ranges_insert_attempt"] += 1

        if stats["nvd_records"] % 10000 == 0:
            conn.commit()
            print(
                f"[PROGRESS] nvd_records={stats['nvd_records']} accepted_refs={stats['cve_github_refs_insert_attempt']}",
                file=sys.stderr,
            )

    conn.commit()

    if args.write_audit:
        write_candidate_audit_csv(out_dir / "accepted_candidate_pairs.csv", accepted_audit)
        write_candidate_audit_csv(out_dir / "rejected_candidate_pairs_sample.csv", rejected_audit)

    return stats


# ------------------------------------------------------------
# GitHub cache loading and version index
# ------------------------------------------------------------

def load_github_cache(conn: sqlite3.Connection, cache_dir: Path) -> Counter:
    stats = Counter()

    version_insert = """
        INSERT OR IGNORE INTO github_versions
        (repo_key, version_raw, version_norm, source, commit_sha, published_at, created_at, cache_file, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    commit_insert = """
        INSERT OR IGNORE INTO github_commits
        (repo_key, commit_sha, commit_date, message, cache_file, raw_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """

    cache_files_by_repo: Dict[str, Set[str]] = defaultdict(set)
    target_repos = {r["repo_key"] for r in conn.execute("SELECT repo_key FROM repositories")}

    for path in iter_cache_files(cache_dir):
        stats["cache_files_seen"] += 1
        path_repo = infer_repo_key_from_path(path)

        for obj in load_cache_json(path):
            items = unwrap_cache_payload(obj)
            obj_repo = infer_repo_key_from_obj(obj)
            base_repo = obj_repo or path_repo

            for item in items:
                if not isinstance(item, dict):
                    continue
                item_repo = infer_repo_key_from_obj(item) or base_repo
                if not item_repo:
                    stats["cache_item_skip_no_repo"] += 1
                    continue
                item_repo = norm_repo_key(item_repo)
                if item_repo not in target_repos:
                    stats["cache_item_skip_repo_not_selected"] += 1
                    continue

                cache_files_by_repo[item_repo].add(str(path))
                kind = classify_cache_item(item, path)

                if kind in {"tag", "release"}:
                    v = extract_version_from_cache_item(item_repo, kind, item, path)
                    if v:
                        conn.execute(
                            version_insert,
                            (
                                v["repo_key"], v["version_raw"], v["version_norm"], v["source"], v["commit_sha"],
                                v["published_at"], v["created_at"], v["cache_file"], v["raw_json"],
                            ),
                        )
                        stats[f"github_{kind}_versions"] += 1
                    continue

                if kind == "commit":
                    c = extract_commit_from_cache_item(item_repo, item, path)
                    if c:
                        conn.execute(
                            commit_insert,
                            (
                                c["repo_key"], c["commit_sha"], c["commit_date"], c["message"], c["cache_file"], c["raw_json"],
                            ),
                        )
                        stats["github_commits"] += 1
                    continue

                stats["cache_item_unknown_kind"] += 1

        if stats["cache_files_seen"] % 1000 == 0:
            conn.commit()
            print(f"[PROGRESS] cache_files_seen={stats['cache_files_seen']}", file=sys.stderr)

    for rk, files in cache_files_by_repo.items():
        conn.execute(
            """
            UPDATE repositories
            SET has_github_cache = 1,
                cache_files_json = ?
            WHERE repo_key = ?
            """,
            (json.dumps(sorted(files), ensure_ascii=False), rk),
        )

    conn.commit()
    return stats


def range_repo_score_ok(rng: Dict[str, Any], repo_key_str: str, args: argparse.Namespace) -> bool:
    owner, repo = split_repo_key(repo_key_str)
    gh = GitHubRepoCandidate(owner=owner, repo=repo, url=f"https://github.com/{owner}/{repo}", source="index_filter")
    cs = score_candidate(
        cve_id=str(rng.get("cve_id") or ""),
        cpe_row=rng,
        gh=gh,
        alpha_owner=args.alpha_owner,
        alpha_repo=args.alpha_repo,
        owner_weight=args.owner_weight,
        threshold=args.threshold,
        ngram=args.ngram,
        compact_mode=args.compact_mode,
        reject_soft_hard=not args.allow_soft_hard,
    )
    return cs.decision == "accept"


def build_version_index(conn: sqlite3.Connection, args: argparse.Namespace) -> Counter:
    stats = Counter()

    versions_by_repo: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in conn.execute("SELECT repo_key, version_raw, version_norm, source FROM github_versions"):
        versions_by_repo[r["repo_key"]].append(dict(r))

    refs_by_pair: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for r in conn.execute("SELECT cve_id, repo_key, github_url FROM cve_github_refs"):
        refs_by_pair[(r["cve_id"], r["repo_key"])].append(r["github_url"])

    ranges_by_cve: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM nvd_cpe_ranges"):
        ranges_by_cve[r["cve_id"]].append(dict(r))

    insert_sql = """
        INSERT OR IGNORE INTO version_cve_index
        (
            cve_id, repo_key, version_raw, version_norm, version_source,
            range_id, cpe_uri, match_reason, github_refs_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    batch: List[Tuple[Any, ...]] = []
    pairs = list(refs_by_pair.keys())

    for idx, (cve_id, rk) in enumerate(pairs, 1):
        versions = versions_by_repo.get(rk, [])
        ranges = ranges_by_cve.get(cve_id, [])
        if not versions:
            stats["pair_skip_no_github_versions"] += 1
            continue
        if not ranges:
            stats["pair_skip_no_nvd_ranges"] += 1
            continue

        refs_json = json.dumps(sorted(refs_by_pair[(cve_id, rk)]), ensure_ascii=False)

        for rng in ranges:
            if args.recheck_range_repo_score_for_index and not range_repo_score_ok(rng, rk, args):
                stats["range_skip_repo_score_recheck_failed"] += 1
                continue

            for ver in versions:
                ok, reason = version_matches_range(ver["version_raw"], rng)
                if not ok:
                    stats[f"version_not_match:{reason}"] += 1
                    continue

                batch.append(
                    (
                        cve_id, rk, ver["version_raw"], ver["version_norm"], ver["source"],
                        rng["range_id"], rng["cpe_uri"], reason, refs_json,
                    )
                )
                stats["version_index_insert_attempt"] += 1

                if len(batch) >= 10000:
                    conn.executemany(insert_sql, batch)
                    batch.clear()

        if idx % 1000 == 0:
            conn.commit()
            print(f"[PROGRESS] indexed_pairs={idx}/{len(pairs)}", file=sys.stderr)

    if batch:
        conn.executemany(insert_sql, batch)
    conn.commit()

    stats["version_index_rows"] = conn.execute("SELECT COUNT(*) AS n FROM version_cve_index").fetchone()["n"]
    return stats


# ------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------

def write_candidate_audit_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(CandidateScore.__annotations__.keys())
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_summary(conn: sqlite3.Connection, out_dir: Path, summary: Dict[str, Any]) -> None:
    for table in [
        "repositories", "cves", "cve_github_refs", "nvd_cpe_ranges",
        "github_versions", "github_commits", "version_cve_index",
    ]:
        n = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        summary[f"rows:{table}"] = n

    with (out_dir / "build_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, sort_keys=True)

    for k, v in summary.items():
        conn.execute(
            """
            INSERT OR REPLACE INTO build_summary(key, value)
            VALUES (?, ?)
            """,
            (str(k), json.dumps(v, ensure_ascii=False)),
        )
    conn.commit()


def dump_csv(conn: sqlite3.Connection, table: str, out_path: Path) -> None:
    cur = conn.execute(f"SELECT * FROM {table}")
    cols = [d[0] for d in cur.description]
    with out_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        while True:
            rows = cur.fetchmany(10000)
            if not rows:
                break
            writer.writerows([tuple(r) for r in rows])


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvd-input", required=True, help="NVD merged JSON/JSONL/GZ 또는 NVD JSON directory")
    ap.add_argument("--github-cache", required=True, help="workspace/github_cache directory")
    ap.add_argument(
        "--git-dir",
        default=None,
        help="sample_*_git 파일들이 들어 있는 directory. 지정하면 해당 repo allowlist 안의 repo만 DB에 등록한다.",
    )
    ap.add_argument(
        "--git-list",
        action="append",
        default=[],
        help="개별 sample git list 파일 경로. 여러 번 지정 가능. --git-dir와 함께 사용할 수 있다.",
    )
    ap.add_argument("--out-workspace", default="workspace_refiltered_nvd2db")
    ap.add_argument("--out-db-name", default="version_cve_refiltered.db")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--write-csv", action="store_true")
    ap.add_argument("--write-audit", action="store_true", help="accepted/rejected candidate pair audit CSV 출력")
    ap.add_argument("--max-rejected-audit-rows", type=int, default=200000)
    ap.add_argument("--skip-version-index", action="store_true")

    ap.add_argument("--alpha-owner", type=float, default=0.8)
    ap.add_argument("--alpha-repo", type=float, default=0.5)
    ap.add_argument("--threshold", type=float, default=0.90)
    ap.add_argument("--owner-weight", type=float, default=0.35)
    ap.add_argument("--ngram", type=int, default=2)
    ap.add_argument("--compact-mode", choices=["sorted", "original", "both_max"], default="sorted")
    ap.add_argument(
        "--allow-soft-hard",
        action="store_true",
        help="기본은 soft/hard non-product token 포함 후보를 reject. 이 옵션을 주면 score만으로 판단.",
    )
    ap.add_argument(
        "--no-recheck-range-repo-score-for-index",
        action="store_true",
        help="version_cve_index 생성 시 range vendor/product와 repo owner/name score 재검사를 생략한다.",
    )

    args = ap.parse_args()
    args.recheck_range_repo_score_for_index = not args.no_recheck_range_repo_score_for_index

    if not (0.0 <= args.alpha_owner <= 1.0):
        raise ValueError("--alpha-owner must be between 0 and 1")
    if not (0.0 <= args.alpha_repo <= 1.0):
        raise ValueError("--alpha-repo must be between 0 and 1")
    if not (0.0 <= args.threshold <= 1.0):
        raise ValueError("--threshold must be between 0 and 1")
    if not (0.0 <= args.owner_weight <= 1.0):
        raise ValueError("--owner-weight must be between 0 and 1")
    if args.ngram <= 0:
        raise ValueError("--ngram must be positive")

    nvd_input = Path(args.nvd_input).resolve()
    github_cache = Path(args.github_cache).resolve()
    git_dir = Path(args.git_dir).resolve() if args.git_dir else None
    git_lists = [Path(p).resolve() for p in args.git_list]
    out_dir = Path(args.out_workspace).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not nvd_input.exists():
        raise FileNotFoundError(nvd_input)
    if not github_cache.exists():
        raise FileNotFoundError(github_cache)
    if git_dir and not git_dir.exists():
        raise FileNotFoundError(git_dir)

    git_sample_sources = load_git_sample_allowlist(git_dir, git_lists)
    args.git_allowlist = set(git_sample_sources.keys())
    args.git_sample_sources = {rk: sorted(srcs) for rk, srcs in git_sample_sources.items()}

    if args.git_allowlist:
        print(f"[INFO] git sample allowlist repos={len(args.git_allowlist)}")
        with (out_dir / "git_sample_allowlist.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["repo_key", "source_files"])
            writer.writeheader()
            for rk in sorted(args.git_allowlist):
                writer.writerow({"repo_key": rk, "source_files": ";".join(args.git_sample_sources.get(rk, []))})
    else:
        print("[WARN] no git sample allowlist supplied; DB will not be restricted to sample_*_git repos", file=sys.stderr)

    out_db = out_dir / args.out_db_name
    if out_db.exists():
        if args.force:
            out_db.unlink()
        else:
            raise RuntimeError(f"output DB exists: {out_db}. use --force")

    conn = connect_db(out_db)
    setup_db(conn)

    print("[STEP 1] parse NVD, filter CPE/version/GitHub URLs, and score CPE↔GitHub mappings")
    nvd_stats = build_from_nvd(conn, nvd_input, args, out_dir)

    print("[STEP 2] load GitHub versions/releases/commits from cache")
    cache_stats = load_github_cache(conn, github_cache)

    index_stats = Counter()
    if not args.skip_version_index:
        print("[STEP 3] build version-CVE index from GitHub versions and selected NVD ranges")
        index_stats = build_version_index(conn, args)
    else:
        print("[STEP 3] skip version-CVE index")

    summary: Dict[str, Any] = {}
    summary.update({f"nvd:{k}": v for k, v in nvd_stats.items()})
    summary.update({f"cache:{k}": v for k, v in cache_stats.items()})
    summary.update({f"index:{k}": v for k, v in index_stats.items()})
    summary.update({
        "policy": "CPE/version filtered NVD records. GitHub repo candidates are selected from ref -> cpe -> description. Reject URL patterns are removed only. CPE vendor/product and GitHub owner/repo are matched by token/compact-key LD+char-ngram cosine fitness score. If git sample allowlist is supplied, only repos in sample_*_git are inserted.",
        "schema": "same_as_02_01_refonly_builder",
        "nvd_input": str(nvd_input),
        "github_cache": str(github_cache),
        "git_dir": str(git_dir) if git_dir else None,
        "git_lists": [str(p) for p in git_lists],
        "git_sample_allowlist_repo_count": len(args.git_allowlist),
        "out_db": str(out_db),
        "out_workspace": str(out_dir),
        "params": {
            "alpha_owner": args.alpha_owner,
            "alpha_repo": args.alpha_repo,
            "threshold": args.threshold,
            "owner_weight": args.owner_weight,
            "ngram": args.ngram,
            "compact_mode": args.compact_mode,
            "git_sample_allowlist_enabled": bool(args.git_allowlist),
            "allow_soft_hard": args.allow_soft_hard,
            "recheck_range_repo_score_for_index": args.recheck_range_repo_score_for_index,
        },
        "note": "Use --git-dir or --git-list to restrict final DB mappings to sample_*_git repos. No LLM is used in this builder; soft/hard token candidates are counted/audited rather than inserted by default.",
    })

    print("[STEP 4] write summary")
    write_summary(conn, out_dir, summary)

    if args.write_csv:
        print("[STEP 5] write CSV outputs")
        for table in [
            "repositories", "cves", "cve_github_refs", "nvd_cpe_ranges",
            "github_versions", "github_commits", "version_cve_index",
        ]:
            out_csv = out_dir / f"{table}.csv"
            dump_csv(conn, table, out_csv)
            print(f"[OK] wrote {out_csv}")

    conn.close()

    print(f"[DONE] DB      = {out_db}")
    print(f"[DONE] summary = {out_dir / 'build_summary.json'}")


if __name__ == "__main__":
    main()
