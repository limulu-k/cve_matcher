#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
03_query_interpreter.py

Query helper for the final range-bound CVE/GitHub/version SQLite DB.

Current target DB schema
------------------------
Core 8 tables:
  build_summary
  cve_github_refs
  cves
  github_commits
  github_versions
  nvd_cpe_ranges
  repositories
  version_cve_index

Main design
-----------
version_cve_index is the authoritative query table.

Supported modes
---------------
1) Repo + version search
   python 03_query_interpreter.py --db DB --git_url https://github.com/owner/repo --version 1.2.3
   python 03_query_interpreter.py --db DB --repo_key owner@repo --version 1.2.3

2) CVE search, case-insensitive
   python 03_query_interpreter.py --db DB --cve_id cve-2025-22923

3) Repo list-up
   python 03_query_interpreter.py --db DB --repo_key owner@repo --ls
   python 03_query_interpreter.py --db DB --repo_key owner@repo --ls --version 1.2.3

4) DB summary
   python 03_query_interpreter.py --db DB --summary
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# Specific GitHub URL forms must come before generic github.com.
# Otherwise api.github.com/repos/OWNER/REPO can be mis-parsed as repos@OWNER.
GITHUB_PATTERNS = [
    re.compile(r"(?:https?://)?api\.github\.com/repos/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"(?:https?://)?raw\.githubusercontent\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"(?:https?://)?codeload\.github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"git\+https?://github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"ssh://git@github\.com[:/]([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"git@github\.com[:/]([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"(?<![A-Za-z0-9_.-])(?:https?://)?(?:www\.)?github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
]

CORE_REQUIRED_TABLES = [
    "build_summary",
    "cve_github_refs",
    "cves",
    "github_commits",
    "github_versions",
    "nvd_cpe_ranges",
    "repositories",
    "version_cve_index",
]


def norm_piece(s: Any) -> str:
    if s is None:
        return ""
    x = str(s).strip().lower()
    if x.endswith(".git"):
        x = x[:-4]
    return x.strip("/@ ")


def normalize_repo_key(repo_key: str) -> str:
    x = str(repo_key or "").strip()
    if not x:
        raise ValueError("empty repo_key")

    if "@" in x:
        owner, repo = x.split("@", 1)
    elif "/" in x:
        owner, repo = x.split("/", 1)
    else:
        raise ValueError(f"repo_key must be owner@repo or owner/repo: {repo_key}")

    owner = norm_piece(owner)
    repo = norm_piece(repo.split("/", 1)[0])
    if not owner or not repo:
        raise ValueError(f"invalid repo_key: {repo_key}")
    return f"{owner}@{repo}"


def repo_key_from_github_url(url: str) -> str:
    for pat in GITHUB_PATTERNS:
        m = pat.search(url or "")
        if not m:
            continue

        owner = norm_piece(m.group(1))
        repo = norm_piece(m.group(2))

        if owner in {"advisories", "topics", "marketplace", "collections", "explore"}:
            raise ValueError(f"not a concrete GitHub repository URL: {url}")

        if repo.startswith("ghsa-"):
            raise ValueError(f"GitHub advisory URL is not a repository URL: {url}")

        if owner and repo:
            return f"{owner}@{repo}"

    raise ValueError(f"cannot parse GitHub owner/repo from URL: {url}")


def resolve_repo_key(git_url: Optional[str], repo_key: Optional[str]) -> str:
    if git_url and repo_key:
        raise ValueError("use only one of --git_url or --repo_key")
    if git_url:
        return repo_key_from_github_url(git_url)
    if repo_key:
        return normalize_repo_key(repo_key)
    raise ValueError("repo search/list mode requires --git_url or --repo_key")


def normalize_cve_id(cve_id: str) -> str:
    x = str(cve_id or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", x):
        raise ValueError(f"invalid CVE ID format: {cve_id}")
    return x


def normalize_version_string(s: Any) -> str:
    if s is None:
        return ""

    raw = str(s).strip()
    if not raw:
        return ""

    x = raw.replace("refs/tags/", "").strip()
    x = re.sub(r"^(release|rel|version|ver|tag|v)[\-_./ ]*", "", x, flags=re.I)

    # Common tags: OpenSSL_1_1_1k, curl-7_80_0, v1.2.3
    m = re.search(r"(\d+(?:[._-]\d+)*(?:[a-zA-Z][0-9]*)?)", x)
    if m:
        x = m.group(1)

    x = x.replace("_", ".").replace("-", ".")
    x = re.sub(r"\.+", ".", x).strip(".")
    return x.lower()


def version_sort_key(s: Any) -> Tuple[Any, ...]:
    ns = normalize_version_string(s)
    parts = re.findall(r"\d+|[a-zA-Z]+", ns)
    key: List[Any] = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p.lower()))
    return tuple(key) if key else ((2, str(s or "").lower()),)


def q_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def connect_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def require_tables(conn: sqlite3.Connection) -> None:
    missing = [t for t in CORE_REQUIRED_TABLES if not table_exists(conn, t)]
    if missing:
        raise RuntimeError(f"missing required DB tables/views: {missing}")


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def parse_github_refs_json(value: Any) -> List[str]:
    """Parse version_cve_index.github_refs_json.

    The v4 builder stores this as JSON list of dictionaries:
      [{"github_url": "...", "ref_kind": "...", "source": "..."}]

    Older scripts treated each dict as str(dict), which made human output messy.
    """
    if value is None:
        return []

    text = str(value).strip()
    if not text:
        return []

    urls: List[str] = []

    try:
        obj = json.loads(text)
    except Exception:
        obj = text

    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                u = x.get("github_url") or x.get("url") or x.get("href")
                if u:
                    urls.append(str(u))
            elif isinstance(x, str):
                urls.append(x)
    elif isinstance(obj, dict):
        u = obj.get("github_url") or obj.get("url") or obj.get("href")
        if u:
            urls.append(str(u))
        # cve_github_refs.reference_json may contain accepted_ranges but usually no urls.
        for k in ["github_urls", "original_github_urls"]:
            xs = obj.get(k)
            if isinstance(xs, list):
                urls.extend(str(x) for x in xs)
    elif isinstance(obj, str):
        urls.append(obj)

    return sorted({u for u in urls if u})


def get_repo_info(conn: sqlite3.Connection, repo_key: str) -> Optional[Dict[str, Any]]:
    if not table_exists(conn, "repositories"):
        return None
    row = conn.execute("SELECT * FROM repositories WHERE repo_key = ?", (repo_key,)).fetchone()
    return row_to_dict(row) if row else None


def get_repo_version_rows(conn: sqlite3.Connection, repo_key: str, input_version: str) -> List[Dict[str, Any]]:
    input_norm = normalize_version_string(input_version)
    rows: List[Dict[str, Any]] = []

    # First try indexed predicates.
    for r in conn.execute(
        """
        SELECT *
        FROM github_versions
        WHERE repo_key = ?
          AND (
            version_raw = ?
            OR lower(version_raw) = lower(?)
            OR version_norm = ?
            OR lower(COALESCE(version_norm, '')) = lower(?)
          )
        ORDER BY version_raw, source
        """,
        (repo_key, input_version, input_version, input_norm, input_norm),
    ):
        rows.append(row_to_dict(r))

    if rows:
        return rows

    # Fallback repo-local normalization scan.
    for r in conn.execute("SELECT * FROM github_versions WHERE repo_key = ?", (repo_key,)):
        d = row_to_dict(r)
        raw = d.get("version_raw")
        norm = d.get("version_norm") or normalize_version_string(raw)
        if normalize_version_string(raw) == input_norm or normalize_version_string(norm) == input_norm:
            rows.append(d)

    return rows


def get_repo_version_count(conn: sqlite3.Connection, repo_key: str) -> int:
    row = conn.execute(
        "SELECT COUNT(DISTINCT version_raw) AS n FROM github_versions WHERE repo_key = ?",
        (repo_key,),
    ).fetchone()
    return int(row["n"]) if row else 0


def get_vci_version_raw_candidates(conn: sqlite3.Connection, repo_key: str, input_version: str) -> List[str]:
    """Map an input version to raw version strings stored in version_cve_index."""
    input_norm = normalize_version_string(input_version)
    candidates = {str(input_version), input_norm}

    for r in get_repo_version_rows(conn, repo_key, input_version):
        if r.get("version_raw"):
            candidates.add(str(r["version_raw"]))
        if r.get("version_norm"):
            candidates.add(str(r["version_norm"]))

    found: set[str] = set()
    for r in conn.execute(
        """
        SELECT DISTINCT version_raw
        FROM version_cve_index
        WHERE repo_key = ?
          AND (
            version_raw = ?
            OR lower(version_raw) = lower(?)
            OR version_norm = ?
            OR lower(COALESCE(version_norm, '')) = lower(?)
          )
        """,
        (repo_key, input_version, input_version, input_norm, input_norm),
    ):
        found.add(str(r["version_raw"]))

    if found:
        return sorted(found, key=version_sort_key)

    # Fallback repo-local normalization scan. This is limited to one repo.
    for r in conn.execute(
        "SELECT DISTINCT version_raw, version_norm FROM version_cve_index WHERE repo_key = ?",
        (repo_key,),
    ):
        raw = r["version_raw"]
        norm = r["version_norm"]
        if normalize_version_string(raw) == input_norm or normalize_version_string(norm) == input_norm:
            found.add(str(raw))

    if found:
        return sorted(found, key=version_sort_key)

    return sorted([x for x in candidates if x], key=version_sort_key)


def enrich_cve_rows(conn: sqlite3.Connection, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not rows:
        return rows

    cve_ids = sorted({str(r.get("cve_id")) for r in rows if r.get("cve_id")})
    if not cve_ids:
        return rows

    qmarks = ",".join("?" for _ in cve_ids)
    cve_map: Dict[str, Dict[str, Any]] = {}
    for r in conn.execute(f"SELECT * FROM cves WHERE cve_id IN ({qmarks})", cve_ids):
        cve_map[str(r["cve_id"])] = row_to_dict(r)

    for r in rows:
        cve = cve_map.get(str(r.get("cve_id")), {})
        for k in ["description", "published", "last_modified", "vuln_status"]:
            r[k] = cve.get(k)
    return rows


def get_refs_for_cve_repo(conn: sqlite3.Connection, cve_id: str, repo_key: str) -> List[str]:
    urls: List[str] = []
    for r in conn.execute(
        """
        SELECT DISTINCT github_url
        FROM cve_github_refs
        WHERE cve_id = ? AND repo_key = ?
        ORDER BY github_url
        """,
        (cve_id, repo_key),
    ):
        urls.append(str(r["github_url"]))
    return urls


def get_range_rows_by_ids(conn: sqlite3.Connection, range_ids: Iterable[Any]) -> Dict[int, Dict[str, Any]]:
    ids = sorted({int(x) for x in range_ids if str(x).isdigit()})
    if not ids:
        return {}
    qmarks = ",".join("?" for _ in ids)
    out: Dict[int, Dict[str, Any]] = {}
    for r in conn.execute(f"SELECT * FROM nvd_cpe_ranges WHERE range_id IN ({qmarks})", ids):
        out[int(r["range_id"])] = row_to_dict(r)
    return out


def group_vci_rows_by_cve(conn: sqlite3.Connection, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}

    range_map = get_range_rows_by_ids(conn, [r.get("range_id") for r in rows])

    for row in rows:
        cve_id = str(row.get("cve_id"))
        repo_key = str(row.get("repo_key"))
        item = grouped.setdefault(
            cve_id,
            {
                "cve_id": cve_id,
                "repo_key": repo_key,
                "versions": [],
                "version_norms": [],
                "description": row.get("description"),
                "published": row.get("published"),
                "last_modified": row.get("last_modified"),
                "vuln_status": row.get("vuln_status"),
                "github_urls": [],
                "index_rows": [],
            },
        )

        if row.get("version_raw"):
            item["versions"].append(str(row["version_raw"]))
        if row.get("version_norm"):
            item["version_norms"].append(str(row["version_norm"]))

        refs = parse_github_refs_json(row.get("github_refs_json"))
        if not refs:
            refs = get_refs_for_cve_repo(conn, cve_id, repo_key)
        item["github_urls"].extend(refs)

        range_id = row.get("range_id")
        rng = range_map.get(int(range_id)) if str(range_id).isdigit() else {}

        index_row = {
            k: row.get(k)
            for k in [
                "cve_id",
                "repo_key",
                "version_raw",
                "version_norm",
                "version_source",
                "range_id",
                "cpe_uri",
                "match_reason",
            ]
            if k in row
        }
        if rng:
            index_row.update(
                {
                    "cpe_vendor": rng.get("vendor"),
                    "cpe_product": rng.get("product"),
                    "cpe_version": rng.get("cpe_version"),
                    "version_start_including": rng.get("version_start_including"),
                    "version_start_excluding": rng.get("version_start_excluding"),
                    "version_end_including": rng.get("version_end_including"),
                    "version_end_excluding": rng.get("version_end_excluding"),
                }
            )
        item["index_rows"].append(index_row)

    out = list(grouped.values())
    for item in out:
        item["versions"] = sorted(set(item["versions"]), key=version_sort_key)
        item["version_norms"] = sorted(set(item["version_norms"]), key=version_sort_key)
        item["github_urls"] = sorted({u for u in item["github_urls"] if u})
        item["matched_index_row_count"] = len(item["index_rows"])
    out.sort(key=lambda x: x["cve_id"])
    return out


def query_repo_version(conn: sqlite3.Connection, repo_key: str, version: str) -> Dict[str, Any]:
    input_norm = normalize_version_string(version)
    raw_candidates = get_vci_version_raw_candidates(conn, repo_key, version)
    repo_version_count = get_repo_version_count(conn, repo_key)
    matched_github_versions = get_repo_version_rows(conn, repo_key, version)
    repo_info = get_repo_info(conn, repo_key)

    qmarks = ",".join("?" for _ in raw_candidates)
    params: List[Any] = [repo_key]
    params.extend(raw_candidates)
    params.extend([version, version, input_norm, input_norm])

    sql = f"""
        SELECT i.*
        FROM version_cve_index AS i
        WHERE i.repo_key = ?
          AND (
            i.version_raw IN ({qmarks})
            OR i.version_raw = ?
            OR lower(i.version_raw) = lower(?)
            OR i.version_norm = ?
            OR lower(COALESCE(i.version_norm, '')) = lower(?)
          )
        ORDER BY i.cve_id, i.version_raw, i.range_id
    """

    raw_rows = [row_to_dict(r) for r in conn.execute(sql, params)]
    raw_rows = enrich_cve_rows(conn, raw_rows)
    matches = group_vci_rows_by_cve(conn, raw_rows)

    return {
        "mode": "repo_version_search",
        "input": {
            "repo_key": repo_key,
            "version": version,
            "version_norm": input_norm,
        },
        "repo": {
            "exists_in_repositories": bool(repo_info),
            "repository_row": repo_info,
            "version_count_in_github_versions": repo_version_count,
            "input_version_exists_in_github_versions": bool(matched_github_versions),
            "matched_github_versions": matched_github_versions,
            "vci_version_raw_candidates": raw_candidates,
        },
        "summary": {
            "status": "ok",
            "affected_cve_count": len(matches),
            "matched_index_row_count": len(raw_rows),
        },
        "matches": matches,
    }


def list_repo_versions(conn: sqlite3.Connection, repo_key: str) -> Dict[str, Any]:
    repo_info = get_repo_info(conn, repo_key)
    rows: List[Dict[str, Any]] = []
    for r in conn.execute(
        """
        SELECT
          repo_key,
          version_raw,
          version_norm,
          GROUP_CONCAT(DISTINCT version_source) AS version_sources,
          COUNT(DISTINCT cve_id) AS cve_count,
          COUNT(*) AS index_row_count
        FROM version_cve_index
        WHERE repo_key = ?
        GROUP BY repo_key, version_raw, version_norm
        """,
        (repo_key,),
    ):
        rows.append(row_to_dict(r))

    rows.sort(key=lambda d: version_sort_key(d.get("version_norm") or d.get("version_raw")))

    return {
        "mode": "repo_version_list",
        "input": {"repo_key": repo_key},
        "repo": {
            "exists_in_repositories": bool(repo_info),
            "repository_row": repo_info,
            "version_count_in_github_versions": get_repo_version_count(conn, repo_key),
        },
        "summary": {
            "status": "ok",
            "version_count_with_cves": len(rows),
            "total_distinct_cve_mentions": sum(int(r.get("cve_count") or 0) for r in rows),
        },
        "versions": rows,
    }


def query_cve(conn: sqlite3.Connection, cve_id: str, limit: int = 0) -> Dict[str, Any]:
    cid = normalize_cve_id(cve_id)

    cve = conn.execute("SELECT * FROM cves WHERE upper(cve_id) = ?", (cid,)).fetchone()
    cve_dict = row_to_dict(cve) if cve else {"cve_id": cid, "status": "not_found_in_cves"}

    refs_by_repo: List[Dict[str, Any]] = []
    for r in conn.execute(
        """
        SELECT
          cve_id,
          repo_key,
          GROUP_CONCAT(DISTINCT github_url) AS github_urls,
          GROUP_CONCAT(DISTINCT ref_kind) AS ref_kinds,
          GROUP_CONCAT(DISTINCT source) AS sources,
          COUNT(*) AS ref_count
        FROM cve_github_refs
        WHERE upper(cve_id) = ?
        GROUP BY cve_id, repo_key
        ORDER BY repo_key
        """,
        (cid,),
    ):
        refs_by_repo.append(row_to_dict(r))

    ranges: List[Dict[str, Any]] = []
    for r in conn.execute(
        """
        SELECT *
        FROM nvd_cpe_ranges
        WHERE upper(cve_id) = ?
        ORDER BY vendor, product, range_id
        """,
        (cid,),
    ):
        ranges.append(row_to_dict(r))

    affected_rows: List[Dict[str, Any]] = []
    sql = """
        SELECT *
        FROM version_cve_index
        WHERE upper(cve_id) = ?
        ORDER BY repo_key, version_raw, range_id
    """
    if limit and limit > 0:
        sql += " LIMIT ?"
        params: Sequence[Any] = (cid, limit)
    else:
        params = (cid,)

    for r in conn.execute(sql, params):
        affected_rows.append(row_to_dict(r))

    repo_summary: Dict[str, Dict[str, Any]] = {}
    for r in affected_rows:
        rk = str(r.get("repo_key"))
        item = repo_summary.setdefault(
            rk,
            {"repo_key": rk, "affected_version_count": 0, "index_row_count": 0, "versions": set(), "range_ids": set()},
        )
        item["index_row_count"] += 1
        if r.get("version_raw"):
            item["versions"].add(str(r["version_raw"]))
        if r.get("range_id") is not None:
            item["range_ids"].add(int(r["range_id"]))

    repo_summary_rows = []
    for item in repo_summary.values():
        versions = sorted(item.pop("versions"), key=version_sort_key)
        range_ids = sorted(item.pop("range_ids"))
        item["affected_version_count"] = len(versions)
        item["versions"] = versions
        item["range_ids"] = range_ids
        repo_summary_rows.append(item)
    repo_summary_rows.sort(key=lambda x: x["repo_key"])

    total_index_count = conn.execute(
        "SELECT COUNT(*) AS n FROM version_cve_index WHERE upper(cve_id) = ?",
        (cid,),
    ).fetchone()["n"]

    return {
        "mode": "cve_search",
        "input": {"cve_id": cid},
        "summary": {
            "status": "ok" if cve else "cve_not_found_in_cves",
            "github_ref_repo_count": len(refs_by_repo),
            "nvd_cpe_range_count": len(ranges),
            "affected_repo_count": len(repo_summary_rows),
            "affected_index_row_count": int(total_index_count),
            "returned_affected_index_row_count": len(affected_rows),
            "limit_applied": bool(limit and limit > 0),
        },
        "cve": cve_dict,
        "github_refs_by_repo": refs_by_repo,
        "nvd_cpe_ranges": ranges,
        "affected_repo_summary": repo_summary_rows,
        "affected_version_rows": affected_rows,
    }


def db_summary(conn: sqlite3.Connection) -> Dict[str, Any]:
    table_counts = []
    for t in CORE_REQUIRED_TABLES:
        n = conn.execute(f"SELECT COUNT(*) AS n FROM {q_ident(t)}").fetchone()["n"]
        table_counts.append({"table": t, "rows": int(n)})

    build_summary = {}
    try:
        for r in conn.execute("SELECT key, value FROM build_summary ORDER BY key"):
            build_summary[str(r["key"])] = str(r["value"])
    except Exception:
        pass

    return {
        "mode": "db_summary",
        "summary": {
            "status": "ok",
            "table_count": len(table_counts),
        },
        "table_counts": table_counts,
        "build_summary": build_summary,
    }


def print_repo_version_human(result: Dict[str, Any]) -> None:
    inp = result["input"]
    repo = result["repo"]
    summary = result["summary"]

    print("== Search: repo + version ==")
    print(f"repo_key     : {inp['repo_key']}")
    print(f"version      : {inp['version']}")
    print(f"version_norm : {inp['version_norm']}")
    print()

    print("== Repo check ==")
    print(f"exists_in_repositories              : {repo.get('exists_in_repositories')}")
    print(f"version_count_in_github_versions    : {repo['version_count_in_github_versions']}")
    print(f"input_version_exists_in_github_versions: {repo['input_version_exists_in_github_versions']}")
    if repo["matched_github_versions"]:
        print("matched_github_versions:")
        for v in repo["matched_github_versions"][:20]:
            print(f"  - {v.get('version_raw')} [{v.get('source')}] commit={v.get('commit_sha')}")
    print()

    print("== Summary ==")
    for k, v in summary.items():
        print(f"{k}: {v}")
    print()

    print("== Affected CVEs ==")
    if not result["matches"]:
        print("(none)")
        return

    for item in result["matches"]:
        print(f"- {item['cve_id']}")
        print(f"  repo       : {item['repo_key']}")
        print(f"  versions   : {', '.join(item.get('versions') or [])}")
        print(f"  status     : {item.get('vuln_status')}")
        print(f"  published  : {item.get('published')}")
        urls = item.get("github_urls") or []
        if urls:
            print(f"  github_urls: {' | '.join(urls[:5])}")
            if len(urls) > 5:
                print(f"               ... +{len(urls) - 5} more")
        desc = item.get("description") or ""
        if desc:
            print(f"  desc       : {' '.join(desc.split())[:300]}")
        print("  index_rows:")
        for r in item.get("index_rows", []):
            range_bits = []
            for k in ["cpe_vendor", "cpe_product", "cpe_version", "version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding"]:
                if r.get(k):
                    range_bits.append(f"{k}={r.get(k)}")
            print(
                "    "
                f"range_id={r.get('range_id')} "
                f"cpe={r.get('cpe_uri')} "
                f"match_reason={r.get('match_reason')} "
                + (" ".join(range_bits) if range_bits else "")
            )


def print_list_versions_human(result: Dict[str, Any]) -> None:
    print("== List: version별 CVE count ==")
    print(f"repo_key: {result['input']['repo_key']}")
    repo = result.get("repo") or {}
    print(f"exists_in_repositories: {repo.get('exists_in_repositories')}")
    print(f"version_count_in_github_versions: {repo.get('version_count_in_github_versions')}")
    print()
    for k, v in result["summary"].items():
        print(f"{k}: {v}")
    print()

    rows = result.get("versions") or []
    if not rows:
        print("(no version-CVE rows)")
        return

    print(f"{'version_raw':30s} {'version_norm':20s} {'cve_count':>10s} {'index_rows':>10s} source")
    print("-" * 90)
    for r in rows:
        print(
            f"{str(r.get('version_raw') or '')[:30]:30s} "
            f"{str(r.get('version_norm') or '')[:20]:20s} "
            f"{int(r.get('cve_count') or 0):10d} "
            f"{int(r.get('index_row_count') or 0):10d} "
            f"{str(r.get('version_sources') or '')}"
        )


def print_cve_human(result: Dict[str, Any]) -> None:
    cve = result.get("cve") or {}
    summary = result.get("summary") or {}

    print("== Search: CVE ==")
    print(f"cve_id       : {result['input']['cve_id']}")
    print(f"status       : {summary.get('status')}")
    print(f"published    : {cve.get('published')}")
    print(f"last_modified: {cve.get('last_modified')}")
    print(f"vuln_status  : {cve.get('vuln_status')}")
    desc = cve.get("description") or ""
    if desc:
        print(f"description  : {' '.join(desc.split())[:700]}")
    print()

    print("== Summary ==")
    for k, v in summary.items():
        print(f"{k}: {v}")
    print()

    print("== GitHub refs by repo ==")
    refs = result.get("github_refs_by_repo") or []
    if not refs:
        print("(none)")
    else:
        for r in refs:
            print(f"- {r.get('repo_key')}")
            print(f"  ref_count: {r.get('ref_count')}")
            print(f"  ref_kinds: {r.get('ref_kinds')}")
            print(f"  urls     : {r.get('github_urls')}")
    print()

    print("== Affected repo/version summary from version_cve_index ==")
    repo_summary = result.get("affected_repo_summary") or []
    if not repo_summary:
        print("(none)")
    else:
        for r in repo_summary:
            versions = r.get("versions") or []
            sample = ", ".join(versions[:20])
            suffix = f" ... +{len(versions) - 20} more" if len(versions) > 20 else ""
            print(
                f"- {r.get('repo_key')}: "
                f"affected_versions={r.get('affected_version_count')} "
                f"index_rows={r.get('index_row_count')} "
                f"range_ids={r.get('range_ids')}"
            )
            if sample:
                print(f"  versions: {sample}{suffix}")


def print_summary_human(result: Dict[str, Any]) -> None:
    print("== DB Summary ==")
    for r in result.get("table_counts", []):
        print(f"{r['table']:24s} {r['rows']:12d}")


def write_csv_result(result: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = result.get("mode")

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)

        if mode == "db_summary":
            w.writerow(["table", "rows"])
            for r in result.get("table_counts", []):
                w.writerow([r.get("table"), r.get("rows")])
            return

        if mode == "repo_version_list":
            w.writerow(["repo_key", "version_raw", "version_norm", "cve_count", "index_row_count", "version_sources"])
            for r in result.get("versions", []):
                w.writerow([
                    r.get("repo_key"),
                    r.get("version_raw"),
                    r.get("version_norm"),
                    r.get("cve_count"),
                    r.get("index_row_count"),
                    r.get("version_sources"),
                ])
            return

        if mode == "cve_search":
            w.writerow([
                "cve_id",
                "repo_key",
                "version_raw",
                "version_norm",
                "version_source",
                "range_id",
                "cpe_uri",
                "match_reason",
            ])
            for r in result.get("affected_version_rows", []):
                w.writerow([
                    r.get("cve_id"),
                    r.get("repo_key"),
                    r.get("version_raw"),
                    r.get("version_norm"),
                    r.get("version_source"),
                    r.get("range_id"),
                    r.get("cpe_uri"),
                    r.get("match_reason"),
                ])
            return

        # repo_version_search or repo version list with --version
        w.writerow([
            "cve_id",
            "repo_key",
            "input_version",
            "matched_versions",
            "published",
            "last_modified",
            "vuln_status",
            "description",
            "github_urls_json",
            "matched_index_row_count",
            "index_rows_json",
        ])
        for item in result.get("matches", []):
            w.writerow([
                item.get("cve_id"),
                item.get("repo_key"),
                (result.get("input") or {}).get("version"),
                ",".join(item.get("versions") or []),
                item.get("published"),
                item.get("last_modified"),
                item.get("vuln_status"),
                item.get("description"),
                json.dumps(item.get("github_urls") or [], ensure_ascii=False),
                item.get("matched_index_row_count"),
                json.dumps(item.get("index_rows") or [], ensure_ascii=False),
            ])


def print_result(result: Dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    if fmt == "csv":
        tmp = Path("/tmp/03_query_interpreter_stdout.csv")
        write_csv_result(result, tmp)
        sys.stdout.write(tmp.read_text(encoding="utf-8"))
        return

    mode = result.get("mode")
    if mode == "db_summary":
        print_summary_human(result)
    elif mode == "repo_version_list":
        print_list_versions_human(result)
    elif mode == "cve_search":
        print_cve_human(result)
    else:
        print_repo_version_human(result)


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Query CVEs by GitHub repo/version or CVE ID from the final range-bound SQLite DB.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument(
        "--db",
        default="workspace_refiltered_v4/version_cve_refiltered.db",
        help="SQLite DB path. Default: workspace_refiltered_v4_binding/version_cve_refiltered.db",
    )

    target = ap.add_mutually_exclusive_group()
    target.add_argument("--git_url", "--github", dest="git_url", default=None, help="GitHub URL, e.g. https://github.com/apache/httpd")
    target.add_argument("--repo_key", default=None, help="Repo key, e.g. apache@httpd")
    target.add_argument("--cve_id", default=None, help="CVE ID, case-insensitive, e.g. CVE-2025-22923")
    target.add_argument("--summary", action="store_true", help="Show DB table counts and build summary")

    ap.add_argument("--version", default=None, help="Version/tag, e.g. 2.4.49 or v2.4.49")
    ap.add_argument("--ls", action="store_true", help="List-up mode for repo. Without --version: version별 CVE count. With --version: full CVE list for that version.")
    ap.add_argument("--limit", type=int, default=0, help="Limit affected_version_rows for --cve_id output. 0 means no limit.")
    ap.add_argument("--json-out", default=None, help="Write full result JSON to file")
    ap.add_argument("--csv-out", default=None, help="Write result CSV to file")
    ap.add_argument("--format", choices=["human", "json", "csv"], default="human", help="Output format")
    return ap


def main() -> None:
    ap = build_arg_parser()
    args = ap.parse_args()

    db = Path(args.db).resolve()
    if not db.exists():
        raise FileNotFoundError(db)

    conn = connect_db(db)
    try:
        require_tables(conn)

        if args.summary:
            if args.ls or args.version:
                raise ValueError("--summary does not use --ls or --version")
            result = db_summary(conn)
        elif args.cve_id:
            if args.ls or args.version:
                raise ValueError("--cve_id search does not use --ls or --version")
            result = query_cve(conn, args.cve_id, limit=args.limit)
        else:
            repo_key = resolve_repo_key(args.git_url, args.repo_key)
            if args.ls:
                if args.version:
                    result = query_repo_version(conn, repo_key, args.version)
                    result["mode"] = "repo_version_list_detail"
                else:
                    result = list_repo_versions(conn, repo_key)
            else:
                if not args.version:
                    raise ValueError("repo search requires --version. Use --ls to list versions.")
                result = query_repo_version(conn, repo_key, args.version)
    finally:
        conn.close()

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.csv_out:
        write_csv_result(result, Path(args.csv_out))

    print_result(result, args.format)


if __name__ == "__main__":
    main()
