#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


GITHUB_PATTERNS = [
    re.compile(r"https?://(?:www\.)?github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"https?://api\.github\.com/repos/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"https?://raw\.githubusercontent\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"git@github\.com[:/]([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
]

WILDCARD_VERSIONS = {"", "*", "-", "n/a", "na", "any", "all", "unspecified", "null", "none"}


def norm_piece(s: Any) -> str:
    if s is None:
        return ""
    x = str(s).strip().lower()
    x = x.replace(".git", "")
    x = x.strip("/@")
    return x


def repo_key_from_github_url(url: str) -> str:
    for pat in GITHUB_PATTERNS:
        m = pat.search(url)
        if not m:
            continue

        owner = norm_piece(m.group(1))
        repo = norm_piece(m.group(2))

        if owner in {"advisories", "topics", "marketplace", "collections", "explore"}:
            raise ValueError(f"not a concrete GitHub repository URL: {url}")

        if repo.startswith("ghsa-"):
            raise ValueError(f"GitHub advisory URL is not a repository URL: {url}")

        if not owner or not repo:
            continue

        return f"{owner}@{repo}"

    raise ValueError(f"cannot parse GitHub owner/repo from URL: {url}")


def normalize_version_string(s: Any) -> str:
    if s is None:
        return ""

    raw = str(s).strip()
    if not raw:
        return ""

    x = raw.replace("refs/tags/", "").strip()

    # v1.2.3, release-1.2.3, version_1_2_3 등 흔한 prefix 제거
    x = re.sub(r"^(release|rel|version|ver|tag|v)[\-_./ ]*", "", x, flags=re.I)

    # OpenSSL_1_1_1k, curl-7_80_0 같은 tag에서 버전 부분 추출
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

        # 1.1.1 < 1.1.1a 같은 식으로 처리
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


def version_matches_range(version: str, rng: Dict[str, Any]) -> Tuple[bool, str]:
    candidate = normalize_version_string(version)

    if not candidate:
        return False, "skip_empty_input_version"

    exact = rng.get("cpe_version")
    start_inc = rng.get("version_start_including")
    start_exc = rng.get("version_start_excluding")
    end_inc = rng.get("version_end_including")
    end_exc = rng.get("version_end_excluding")

    has_range = any(x not in (None, "", "null") for x in [start_inc, start_exc, end_inc, end_exc])

    # exact CPE version
    if exact is not None and str(exact).strip().lower() not in WILDCARD_VERSIONS and not has_range:
        c = cmp_version(candidate, exact)
        if c is not None and c == 0:
            return True, "exact_cpe_version_match"

        if normalize_version_string(candidate) == normalize_version_string(exact):
            return True, "exact_cpe_version_string_match"

        return False, "not_exact_cpe_version"

    # version = * 이고 range도 없으면 affected 여부 계산 불가
    if not has_range:
        return False, "skip_no_usable_version_range"

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
    required = ["cve_github_refs", "github_versions", "nvd_cpe_ranges", "cves"]

    missing = [t for t in required if not table_exists(conn, t)]

    if missing:
        raise RuntimeError(f"missing required DB tables/views: {missing}")


def get_version_rows(conn: sqlite3.Connection, repo_key: str, input_version: str) -> List[Dict[str, Any]]:
    input_norm = normalize_version_string(input_version)

    rows = []
    for r in conn.execute(
        """
        SELECT
          repo_key,
          version_raw,
          version_norm,
          source,
          commit_sha,
          published_at,
          created_at
        FROM github_versions
        WHERE repo_key = ?
        """,
        (repo_key,),
    ):
        d = dict(r)
        raw = d.get("version_raw")
        norm = d.get("version_norm") or normalize_version_string(raw)

        if str(raw) == input_version:
            rows.append(d)
            continue

        if normalize_version_string(raw) == input_norm:
            rows.append(d)
            continue

        if norm and normalize_version_string(norm) == input_norm:
            rows.append(d)
            continue

    return rows


def get_repo_version_count(conn: sqlite3.Connection, repo_key: str) -> int:
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT version_raw) AS n
        FROM github_versions
        WHERE repo_key = ?
        """,
        (repo_key,),
    ).fetchone()
    return int(row["n"]) if row else 0


def get_candidate_cves(conn: sqlite3.Connection, repo_key: str) -> List[Dict[str, Any]]:
    rows = []
    for r in conn.execute(
        """
        SELECT
          g.cve_id,
          g.repo_key,
          GROUP_CONCAT(DISTINCT g.github_url) AS github_urls,
          GROUP_CONCAT(DISTINCT g.ref_kind) AS ref_kinds,
          c.description,
          c.published,
          c.last_modified,
          c.vuln_status
        FROM cve_github_refs g
        LEFT JOIN cves c
          ON g.cve_id = c.cve_id
        WHERE g.repo_key = ?
        GROUP BY g.cve_id, g.repo_key
        ORDER BY g.cve_id
        """,
        (repo_key,),
    ):
        rows.append(dict(r))
    return rows


def get_ranges_for_cve(conn: sqlite3.Connection, cve_id: str) -> List[Dict[str, Any]]:
    rows = []
    for r in conn.execute(
        """
        SELECT
          range_id,
          cve_id,
          cpe_uri,
          part,
          vendor,
          product,
          cpe_version,
          version_start_including,
          version_start_excluding,
          version_end_including,
          version_end_excluding,
          vulnerable,
          match_criteria_id
        FROM nvd_cpe_ranges
        WHERE cve_id = ?
        """,
        (cve_id,),
    ):
        rows.append(dict(r))
    return rows


def query_cves(
    conn: sqlite3.Connection,
    github_url: str,
    version: str,
    require_existing_version: bool,
    include_nonaffected: bool,
) -> Dict[str, Any]:
    repo_key = repo_key_from_github_url(github_url)
    input_norm = normalize_version_string(version)

    version_rows = get_version_rows(conn, repo_key, version)
    repo_version_count = get_repo_version_count(conn, repo_key)
    version_exists = len(version_rows) > 0

    result: Dict[str, Any] = {
        "input": {
            "github_url": github_url,
            "repo_key": repo_key,
            "version": version,
            "version_norm": input_norm,
            "require_existing_version": require_existing_version,
        },
        "repo": {
            "version_count_in_db": repo_version_count,
            "input_version_exists_in_github_versions": version_exists,
            "matched_github_versions": version_rows,
        },
        "summary": {},
        "matches": [],
        "nonaffected_candidates": [],
        "skipped": [],
    }

    if require_existing_version and not version_exists:
        result["summary"] = {
            "status": "version_not_found",
            "candidate_cve_count": 0,
            "affected_cve_count": 0,
            "message": "입력 version이 github_versions에 존재하지 않아서 CVE 매칭을 중단했다. --allow-nonexistent-version 옵션을 주면 가상 버전으로 range 비교만 수행한다.",
        }
        return result

    candidate_cves = get_candidate_cves(conn, repo_key)

    affected = []
    nonaffected = []
    skipped = []

    for cve in candidate_cves:
        cve_id = cve["cve_id"]
        ranges = get_ranges_for_cve(conn, cve_id)

        if not ranges:
            skipped.append(
                {
                    "cve_id": cve_id,
                    "reason": "no_nvd_cpe_ranges",
                    "repo_key": repo_key,
                    "github_urls": cve.get("github_urls"),
                    "description": cve.get("description"),
                }
            )
            continue

        matched_ranges = []
        checked_ranges = []

        for rng in ranges:
            ok, reason = version_matches_range(version, rng)
            row = dict(rng)
            row["match_result"] = reason

            checked_ranges.append(row)

            if ok:
                matched_ranges.append(row)

        if matched_ranges:
            affected.append(
                {
                    "cve_id": cve_id,
                    "repo_key": repo_key,
                    "version": version,
                    "version_norm": input_norm,
                    "github_urls": cve.get("github_urls"),
                    "ref_kinds": cve.get("ref_kinds"),
                    "description": cve.get("description"),
                    "published": cve.get("published"),
                    "last_modified": cve.get("last_modified"),
                    "vuln_status": cve.get("vuln_status"),
                    "matched_ranges": matched_ranges,
                }
            )
        else:
            nonaffected.append(
                {
                    "cve_id": cve_id,
                    "repo_key": repo_key,
                    "version": version,
                    "github_urls": cve.get("github_urls"),
                    "description": cve.get("description"),
                    "checked_ranges": checked_ranges,
                }
            )

    result["matches"] = affected

    if include_nonaffected:
        result["nonaffected_candidates"] = nonaffected
    else:
        result["nonaffected_candidates"] = []

    result["skipped"] = skipped

    result["summary"] = {
        "status": "ok",
        "candidate_cve_count": len(candidate_cves),
        "affected_cve_count": len(affected),
        "nonaffected_candidate_count": len(nonaffected),
        "skipped_no_range_count": len(skipped),
    }

    return result


def print_human(result: Dict[str, Any]) -> None:
    inp = result["input"]
    repo = result["repo"]
    summary = result["summary"]

    print("== Input ==")
    print(f"github_url: {inp['github_url']}")
    print(f"repo_key  : {inp['repo_key']}")
    print(f"version   : {inp['version']}")
    print(f"version_norm: {inp['version_norm']}")
    print()

    print("== Repo version check ==")
    print(f"version_count_in_db: {repo['version_count_in_db']}")
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
        print(f"  version    : {item['version']}")
        print(f"  ref_kinds  : {item.get('ref_kinds')}")
        print(f"  github_urls: {item.get('github_urls')}")

        desc = item.get("description") or ""
        if desc:
            desc_one = " ".join(desc.split())
            print(f"  desc       : {desc_one[:300]}")

        print("  matched_ranges:")
        for r in item["matched_ranges"]:
            print(
                "    "
                f"range_id={r.get('range_id')} "
                f"cpe={r.get('cpe_uri')} "
                f"version={r.get('cpe_version')} "
                f"start_inc={r.get('version_start_including')} "
                f"start_exc={r.get('version_start_excluding')} "
                f"end_inc={r.get('version_end_including')} "
                f"end_exc={r.get('version_end_excluding')} "
                f"reason={r.get('match_result')}"
            )


def write_csv(result: Dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "cve_id",
                "repo_key",
                "input_version",
                "github_urls",
                "ref_kinds",
                "description",
                "matched_range_count",
                "matched_ranges_json",
            ]
        )

        for item in result["matches"]:
            w.writerow(
                [
                    item.get("cve_id"),
                    item.get("repo_key"),
                    item.get("version"),
                    item.get("github_urls"),
                    item.get("ref_kinds"),
                    item.get("description"),
                    len(item.get("matched_ranges") or []),
                    json.dumps(item.get("matched_ranges") or [], ensure_ascii=False),
                ]
            )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", help="version_cve_refonly.db path", default="workspace_refonly_nvd_cache/version_cve_refonly.db")
    ap.add_argument("--github", required=True, help="GitHub URL, e.g. https://github.com/apache/httpd")
    ap.add_argument("--version", required=True, help="version/tag, e.g. 2.4.49 or v2.4.49")
    ap.add_argument(
        "--allow-nonexistent-version",
        action="store_true",
        help="github_versions에 실제 존재하지 않아도 가상 version으로 range 비교 수행",
    )
    ap.add_argument(
        "--include-nonaffected",
        action="store_true",
        help="candidate였지만 version range에 안 걸린 CVE도 JSON 출력에 포함",
    )
    ap.add_argument("--json-out", default=None, help="write full result JSON")
    ap.add_argument("--csv-out", default=None, help="write affected CVE CSV")
    ap.add_argument("--format", choices=["human", "json"], default="human")

    args = ap.parse_args()

    db = Path(args.db).resolve()

    if not db.exists():
        raise FileNotFoundError(db)

    conn = connect_db(db)
    require_tables(conn)

    result = query_cves(
        conn=conn,
        github_url=args.github,
        version=args.version,
        require_existing_version=not args.allow_nonexistent_version,
        include_nonaffected=args.include_nonaffected,
    )

    conn.close()

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.csv_out:
        out = Path(args.csv_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        write_csv(result, out)

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_human(result)


if __name__ == "__main__":
    main()
