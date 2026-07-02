#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
build_refonly_from_nvd_cache.py

목표:
  기존 오염 DB/CSV를 전혀 보지 않고,
  NVD merged JSON + GitHub cache만으로
  "GitHub reference가 직접 존재하는 CVE-repo"만 새 DB에 등록한다.

입력:
  --nvd-input
    NVD merged json/jsonl/json.gz 또는 NVD json들이 들어 있는 directory

  --github-cache
    기존 workspace/github_cache 디렉터리
    GitHub tag/release/commit API 응답 cache를 재사용한다.

정책:
  - NVD reference URL 안에 github.com/owner/repo가 직접 있어야 CVE↔repo 등록
  - CPE vendor/product 이름으로 repo를 추론하지 않음
  - CPE는 affected range evidence로만 저장
  - repo version은 GitHub cache에서만 읽음
  - GitHub API 재호출 없음

출력 DB:
  repositories
  cves
  cve_github_refs
  github_versions
  github_commits
  nvd_cpe_ranges
  version_cve_index
  build_summary
"""

import argparse
import csv
import gzip
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple


try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)


# ------------------------------------------------------------
# Regex / normalization
# ------------------------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

GITHUB_REPOS = [
    re.compile(r"https?://(?:www\.)?github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"https?://api\.github\.com/repos/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"https?://raw\.githubusercontent\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"git@github\.com[:/]([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
]

GITHUB_URL_RE = re.compile(
    r"(?:https?://(?:www\.)?github\.com/[^\s\"'<>]+|"
    r"https?://api\.github\.com/repos/[^\s\"'<>]+|"
    r"https?://raw\.githubusercontent\.com/[^\s\"'<>]+|"
    r"git@github\.com[:/][^\s\"'<>]+)",
    re.I,
)

COMMIT_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.I)
RELEASE_TAG_RE = re.compile(r"/releases/tag/([^/\s\"'<>#?]+)", re.I)
TREE_TAG_RE = re.compile(r"/tree/([^/\s\"'<>#?]+)", re.I)
COMPARE_RE = re.compile(r"/compare/([^/\s\"'<>#?]+)", re.I)
PULL_RE = re.compile(r"/pull/(\d+)", re.I)
ISSUE_RE = re.compile(r"/issues/(\d+)", re.I)


def qi(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


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


def is_pseudo_github_repo(owner: str, repo: str) -> bool:
    owner = norm_piece(owner)
    repo = norm_piece(repo)

    if owner in {"advisories", "topics", "marketplace", "collections", "explore"}:
        return True
    if repo.startswith("ghsa-"):
        return True
    return False


def extract_github_repo_keys(text: str) -> Set[str]:
    out = set()
    if not text:
        return out

    for pat in GITHUB_REPOS:
        for owner, repo in pat.findall(text):
            if is_pseudo_github_repo(owner, repo):
                continue
            rk = repo_key(owner, repo)
            if rk:
                out.add(rk)

    return out


def extract_github_urls(text: str) -> List[str]:
    if not text:
        return []
    return sorted(set(m.group(0).rstrip("),.;") for m in GITHUB_URL_RE.finditer(text)))


def github_url_to_repo_key(url: str) -> Optional[str]:
    if not url:
        return None

    for pat in GITHUB_REPOS:
        m = pat.search(url)
        if not m:
            continue
        owner, repo = m.group(1), m.group(2)
        if is_pseudo_github_repo(owner, repo):
            return None
        rk = repo_key(owner, repo)
        return rk or None

    return None


def classify_github_url(url: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    return: ref_kind, commit_sha, tag_name
    """
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


def safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return str(obj)


# ------------------------------------------------------------
# Version normalization / comparison
# ------------------------------------------------------------

WILDCARD_VERSIONS = {"", "*", "-", "n/a", "na", "any", "all", "unspecified"}


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
        if p.isdigit():
            out.append(int(p))
        else:
            out.append(p.lower())

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
            if va == 0:
                return -1
            return 1

        if isinstance(va, str) and isinstance(vb, int):
            if vb == 0:
                return 1
            return -1

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
# CPE parsing
# ------------------------------------------------------------

def split_cpe23(cpe_uri: str) -> List[str]:
    """
    cpe:2.3:a:vendor:product:version:...
    backslash escape를 단순 처리.
    """
    parts = []
    cur = []
    esc = False

    for ch in cpe_uri:
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

    result = {
        "part": None,
        "vendor": None,
        "product": None,
        "version": None,
    }

    if not cpe_uri.startswith("cpe:2.3:"):
        return result

    parts = split_cpe23(cpe_uri)

    # cpe, 2.3, part, vendor, product, version, ...
    if len(parts) >= 6:
        result["part"] = parts[2]
        result["vendor"] = parts[3]
        result["product"] = parts[4]
        result["version"] = parts[5]

    return result


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


# ------------------------------------------------------------
# NVD input parsing
# ------------------------------------------------------------

def open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def load_json_or_jsonl(path: Path) -> Iterable[Any]:
    """
    JSON file이면 object/list 하나를 yield.
    JSONL이면 line별 dict yield.
    """
    with open_text(path) as f:
        prefix = f.read(4096)
        f.seek(0)

        stripped = prefix.lstrip()

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                yield json.load(f)
                return
            except Exception:
                pass

        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def find_nvd_files(nvd_input: Path) -> List[Path]:
    if nvd_input.is_file():
        return [nvd_input]

    files = []
    for p in nvd_input.rglob("*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")):
            files.append(p)

    return sorted(files)


def iter_nvd_records(nvd_input: Path) -> Iterator[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """
    yield: cve_obj, raw_record
    """
    for path in find_nvd_files(nvd_input):
        print(f"[NVD] reading {path}", file=sys.stderr)

        for obj in load_json_or_jsonl(path):
            # NVD 2.0 feed
            if isinstance(obj, dict) and isinstance(obj.get("vulnerabilities"), list):
                for item in obj["vulnerabilities"]:
                    if not isinstance(item, dict):
                        continue
                    cve = item.get("cve")
                    if isinstance(cve, dict):
                        yield cve, item
                continue

            # NVD legacy 1.1 feed
            if isinstance(obj, dict) and isinstance(obj.get("CVE_Items"), list):
                for item in obj["CVE_Items"]:
                    if not isinstance(item, dict):
                        continue
                    cve = item.get("cve")
                    if isinstance(cve, dict):
                        yield cve, item
                continue

            # merged list
            if isinstance(obj, list):
                for item in obj:
                    if not isinstance(item, dict):
                        continue
                    if isinstance(item.get("cve"), dict):
                        yield item["cve"], item
                    elif CVE_RE.search(safe_json(item)):
                        yield item, item
                continue

            # single record
            if isinstance(obj, dict):
                if isinstance(obj.get("cve"), dict):
                    yield obj["cve"], obj
                elif CVE_RE.search(safe_json(obj)):
                    yield obj, obj


def extract_cve_id(cve: Dict[str, Any], raw: Dict[str, Any]) -> Optional[str]:
    for v in [
        cve.get("id"),
        cve.get("CVE_data_meta", {}).get("ID") if isinstance(cve.get("CVE_data_meta"), dict) else None,
        raw.get("cve_id"),
        raw.get("id"),
    ]:
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
    repos = extract_github_repo_keys(text)

    if len(repos) == 1:
        return next(iter(repos))

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
    """
    cache 구조가 dict/list 무엇이든 내부 list 후보를 펼침.
    """
    if isinstance(obj, list):
        return obj

    if not isinstance(obj, dict):
        return []

    for key in ["data", "items", "result", "response"]:
        if isinstance(obj.get(key), list):
            return obj[key]

    combined = []
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
# DB setup
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


# ------------------------------------------------------------
# Build steps
# ------------------------------------------------------------

def insert_repository(conn: sqlite3.Connection, repo: str) -> None:
    owner, name = split_repo_key(repo)
    conn.execute(
        """
        INSERT OR IGNORE INTO repositories(repo_key, owner, repo)
        VALUES (?, ?, ?)
        """,
        (repo, owner, name),
    )


def build_from_nvd(conn: sqlite3.Connection, nvd_input: Path, require_github_ref: bool = True) -> Counter:
    stats = Counter()

    cve_insert = """
        INSERT OR IGNORE INTO cves
        (cve_id, published, last_modified, vuln_status, description)
        VALUES (?, ?, ?, ?, ?)
    """

    ref_insert = """
        INSERT OR IGNORE INTO cve_github_refs
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

    seen_ranges = set()

    for cve, raw in iter_nvd_records(nvd_input):
        stats["nvd_records"] += 1

        cve_id = extract_cve_id(cve, raw)
        if not cve_id:
            stats["skip_no_cve_id"] += 1
            continue

        refs = extract_references(cve, raw)
        github_ref_rows = []

        for ref in refs:
            url = str(ref.get("url") or ref.get("href") or "")
            if not url:
                continue

            rk = github_url_to_repo_key(url)
            if not rk:
                continue

            ref_kind, commit_sha, tag_name = classify_github_url(url)

            github_ref_rows.append(
                {
                    "repo_key": rk,
                    "url": url,
                    "ref_kind": ref_kind,
                    "commit_sha": commit_sha,
                    "tag_name": tag_name,
                    "source": ref.get("source") or ref.get("refsource"),
                    "reference_json": safe_json(ref),
                }
            )

        if require_github_ref and not github_ref_rows:
            stats["skip_no_github_reference"] += 1
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

        for gr in github_ref_rows:
            insert_repository(conn, gr["repo_key"])
            conn.execute(
                ref_insert,
                (
                    cve_id,
                    gr["repo_key"],
                    gr["url"],
                    gr["ref_kind"],
                    gr["commit_sha"],
                    gr["tag_name"],
                    gr["source"],
                    gr["reference_json"],
                ),
            )
            stats["github_ref_rows"] += 1

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
                row["cve_id"],
                row["cpe_uri"],
                row["version_start_including"],
                row["version_start_excluding"],
                row["version_end_including"],
                row["version_end_excluding"],
            )

            if key in seen_ranges:
                continue

            seen_ranges.add(key)

            conn.execute(
                range_insert,
                (
                    row["cve_id"],
                    row["cpe_uri"],
                    row["part"],
                    row["vendor"],
                    row["product"],
                    row["cpe_version"],
                    row["version_start_including"],
                    row["version_start_excluding"],
                    row["version_end_including"],
                    row["version_end_excluding"],
                    row["vulnerable"],
                    row["match_criteria_id"],
                    row["raw_json"],
                ),
            )
            stats["nvd_cpe_ranges"] += 1

        if stats["nvd_records"] % 10000 == 0:
            conn.commit()
            print(f"[PROGRESS] nvd_records={stats['nvd_records']} github_refs={stats['github_ref_rows']}", file=sys.stderr)

    conn.commit()
    return stats


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

    cache_files_by_repo = defaultdict(set)

    direct_repos = {
        r["repo_key"]
        for r in conn.execute("SELECT repo_key FROM repositories")
    }

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

                # direct GitHub reference로 등록된 repo만 cache 사용
                if item_repo not in direct_repos:
                    stats["cache_item_skip_repo_not_direct_ref"] += 1
                    continue

                cache_files_by_repo[item_repo].add(str(path))

                kind = classify_cache_item(item, path)

                if kind in {"tag", "release"}:
                    v = extract_version_from_cache_item(item_repo, kind, item, path)
                    if v:
                        conn.execute(
                            version_insert,
                            (
                                v["repo_key"],
                                v["version_raw"],
                                v["version_norm"],
                                v["source"],
                                v["commit_sha"],
                                v["published_at"],
                                v["created_at"],
                                v["cache_file"],
                                v["raw_json"],
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
                                c["repo_key"],
                                c["commit_sha"],
                                c["commit_date"],
                                c["message"],
                                c["cache_file"],
                                c["raw_json"],
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


def build_version_index(conn: sqlite3.Connection) -> Counter:
    stats = Counter()

    versions_by_repo = defaultdict(list)
    for r in conn.execute(
        """
        SELECT repo_key, version_raw, version_norm, source
        FROM github_versions
        """
    ):
        versions_by_repo[r["repo_key"]].append(dict(r))

    refs_by_pair = defaultdict(list)
    for r in conn.execute(
        """
        SELECT cve_id, repo_key, github_url
        FROM cve_github_refs
        """
    ):
        refs_by_pair[(r["cve_id"], r["repo_key"])].append(r["github_url"])

    ranges_by_cve = defaultdict(list)
    for r in conn.execute(
        """
        SELECT *
        FROM nvd_cpe_ranges
        """
    ):
        ranges_by_cve[r["cve_id"]].append(dict(r))

    insert_sql = """
        INSERT OR IGNORE INTO version_cve_index
        (
            cve_id, repo_key, version_raw, version_norm, version_source,
            range_id, cpe_uri, match_reason, github_refs_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    batch = []

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
            for ver in versions:
                ok, reason = version_matches_range(ver["version_raw"], rng)
                if not ok:
                    stats[f"version_not_match:{reason}"] += 1
                    continue

                batch.append(
                    (
                        cve_id,
                        rk,
                        ver["version_raw"],
                        ver["version_norm"],
                        ver["source"],
                        rng["range_id"],
                        rng["cpe_uri"],
                        reason,
                        refs_json,
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

    stats["version_index_rows"] = conn.execute(
        "SELECT COUNT(*) AS n FROM version_cve_index"
    ).fetchone()["n"]

    return stats


def write_summary(conn: sqlite3.Connection, out_dir: Path, summary: Dict[str, Any]) -> None:
    for table in [
        "repositories",
        "cves",
        "cve_github_refs",
        "nvd_cpe_ranges",
        "github_versions",
        "github_commits",
        "version_cve_index",
    ]:
        n = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        summary[f"rows:{table}"] = n

    with (out_dir / "build_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

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

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(cols)

        while True:
            rows = cur.fetchmany(10000)
            if not rows:
                break
            writer.writerows([tuple(r) for r in rows])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvd-input", required=True, help="NVD merged JSON/JSONL/GZ 또는 NVD JSON directory")
    ap.add_argument("--github-cache", required=True, help="workspace/github_cache directory")
    ap.add_argument("--out-workspace", default="workspace_refonly_nvd_cache")
    ap.add_argument("--out-db-name", default="version_cve_refonly.db")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--write-csv", action="store_true")
    ap.add_argument("--skip-version-index", action="store_true")
    args = ap.parse_args()

    nvd_input = Path(args.nvd_input).resolve()
    github_cache = Path(args.github_cache).resolve()
    out_dir = Path(args.out_workspace).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not nvd_input.exists():
        raise FileNotFoundError(nvd_input)

    if not github_cache.exists():
        raise FileNotFoundError(github_cache)

    out_db = out_dir / args.out_db_name

    if out_db.exists():
        if args.force:
            out_db.unlink()
        else:
            raise RuntimeError(f"output DB exists: {out_db}. use --force")

    conn = connect_db(out_db)
    setup_db(conn)

    print("[STEP 1] parse NVD and register only direct GitHub references")
    nvd_stats = build_from_nvd(conn, nvd_input)

    print("[STEP 2] load GitHub versions/releases/commits from cache")
    cache_stats = load_github_cache(conn, github_cache)

    index_stats = Counter()
    if not args.skip_version_index:
        print("[STEP 3] build version-CVE index from GitHub versions and NVD ranges")
        index_stats = build_version_index(conn)
    else:
        print("[STEP 3] skip version-CVE index")

    summary = {}
    summary.update({f"nvd:{k}": v for k, v in nvd_stats.items()})
    summary.update({f"cache:{k}": v for k, v in cache_stats.items()})
    summary.update({f"index:{k}": v for k, v in index_stats.items()})
    summary.update(
        {
            "policy": "Only direct GitHub URLs in NVD references create CVE-repo mappings. No old DB, no cve_repo_edges.csv, no CPE product-to-repo inference.",
            "nvd_input": str(nvd_input),
            "github_cache": str(github_cache),
            "out_db": str(out_db),
            "out_workspace": str(out_dir),
        }
    )

    print("[STEP 4] write summary")
    write_summary(conn, out_dir, summary)

    if args.write_csv:
        print("[STEP 5] write CSV outputs")
        for table in [
            "repositories",
            "cves",
            "cve_github_refs",
            "nvd_cpe_ranges",
            "github_versions",
            "github_commits",
            "version_cve_index",
        ]:
            out_csv = out_dir / f"{table}.csv"
            dump_csv(conn, table, out_csv)
            print(f"[OK] wrote {out_csv}")

    conn.close()

    print(f"[DONE] DB      = {out_db}")
    print(f"[DONE] summary = {out_dir / 'build_summary.json'}")


if __name__ == "__main__":
    main()
