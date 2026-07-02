#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set, Tuple


OWNER_REPO_AT = re.compile(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+$")
OWNER_REPO_SLASH = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)",
    re.I,
)

CACHE_FILE_RE = re.compile(
    r"^(.+?)__(.+?)__(tags|releases)__page_(\d+)\.json(?:\.gz)?$",
    re.I,
)


def norm_piece(x: Any) -> str:
    if x is None:
        return ""
    s = str(x).strip().lower()
    s = s.replace(".git", "")
    s = s.strip("/@")
    return s


def norm_repo_key(x: Any) -> str:
    if x is None:
        return ""
    s = str(x).strip().lower()
    s = s.replace(".git", "")
    s = s.replace("/", "@")
    s = s.strip("/@")
    return s


def make_repo_key(owner: Any, repo: Any) -> str:
    owner = norm_piece(owner)
    repo = norm_piece(repo)
    if not owner or not repo:
        return ""
    return f"{owner}@{repo}"


def parse_git_line(line: str) -> Set[str]:
    repos = set()
    line = line.strip()

    if not line or line.startswith("#"):
        return repos

    if line.startswith("{"):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                for k in ["repo_key", "git_key", "repository", "repo", "github_repo"]:
                    if isinstance(obj.get(k), str):
                        rk = norm_repo_key(obj[k])
                        if rk:
                            repos.add(rk)

                owner = obj.get("owner") or obj.get("repo_owner")
                repo = obj.get("repo_name") or obj.get("name")
                if owner and repo:
                    rk = make_repo_key(owner, repo)
                    if rk:
                        repos.add(rk)
        except Exception:
            pass

    for owner, repo in GITHUB_URL_RE.findall(line):
        rk = make_repo_key(owner, repo)
        if rk:
            repos.add(rk)

    for token in re.split(r"[\s,;\t]+", line):
        token = token.strip().strip("\"'`")
        token = token.replace(".git", "")

        if OWNER_REPO_AT.fullmatch(token):
            repos.add(norm_repo_key(token))
        elif OWNER_REPO_SLASH.fullmatch(token):
            repos.add(norm_repo_key(token))

    return repos


def load_git_repos(git_dir: Path) -> Dict[str, Set[str]]:
    repo_sources = defaultdict(set)

    if not git_dir.exists():
        raise FileNotFoundError(f"git dir not found: {git_dir}")

    for p in git_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.name.startswith("._"):
            continue

        try:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for rk in parse_git_line(line):
                        repo_sources[rk].add(str(p))
        except Exception:
            continue

    return repo_sources


def parse_cache_filename(path: Path) -> Optional[Tuple[str, str, int]]:
    m = CACHE_FILE_RE.match(path.name)
    if not m:
        return None

    owner, repo, kind, page = m.group(1), m.group(2), m.group(3), int(m.group(4))
    rk = make_repo_key(owner, repo)

    if not rk:
        return None

    return rk, kind.lower(), page


def load_cache_repos(cache_dir: Path) -> Dict[str, Dict[str, Any]]:
    cache = {}

    if not cache_dir.exists():
        raise FileNotFoundError(f"cache dir not found: {cache_dir}")

    for p in cache_dir.rglob("*"):
        if not p.is_file():
            continue

        parsed = parse_cache_filename(p)
        if not parsed:
            continue

        rk, kind, page = parsed

        if rk not in cache:
            cache[rk] = {
                "repo_key": rk,
                "tags_file_count": 0,
                "releases_file_count": 0,
                "tags_bytes": 0,
                "releases_bytes": 0,
                "empty_tags_files": 0,
                "empty_releases_files": 0,
            }

        size = p.stat().st_size

        if kind == "tags":
            cache[rk]["tags_file_count"] += 1
            cache[rk]["tags_bytes"] += size
            if size <= 2:
                cache[rk]["empty_tags_files"] += 1

        elif kind == "releases":
            cache[rk]["releases_file_count"] += 1
            cache[rk]["releases_bytes"] += size
            if size <= 2:
                cache[rk]["empty_releases_files"] += 1

    for rk, d in cache.items():
        d["has_tags_cache"] = d["tags_file_count"] > 0
        d["has_releases_cache"] = d["releases_file_count"] > 0
        d["has_any_cache"] = d["has_tags_cache"] or d["has_releases_cache"]

    return cache


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def load_db_ref_repos(db_path: Path) -> Dict[str, Dict[str, Any]]:
    if not db_path.exists():
        raise FileNotFoundError(f"db not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    if not table_exists(conn, "cve_github_refs"):
        conn.close()
        raise RuntimeError("DB에 cve_github_refs 테이블이 없음")

    sql = """
    SELECT
      repo_key,
      COUNT(*) AS ref_rows,
      COUNT(DISTINCT cve_id) AS cve_count,
      SUM(CASE WHEN ref_kind = 'commit' THEN 1 ELSE 0 END) AS commit_ref_rows,
      SUM(CASE WHEN ref_kind = 'tag' THEN 1 ELSE 0 END) AS tag_ref_rows,
      SUM(CASE WHEN ref_kind = 'release' THEN 1 ELSE 0 END) AS release_ref_rows,
      MIN(cve_id) AS sample_cve
    FROM cve_github_refs
    WHERE repo_key IS NOT NULL
      AND repo_key <> ''
      AND github_url IS NOT NULL
      AND github_url <> ''
      AND github_url LIKE '%github.com/%'
    GROUP BY repo_key
    """

    out = {}

    for r in conn.execute(sql):
        rk = norm_repo_key(r["repo_key"])
        if not rk:
            continue

        out[rk] = {
            "repo_key": rk,
            "ref_rows": int(r["ref_rows"] or 0),
            "cve_count": int(r["cve_count"] or 0),
            "commit_ref_rows": int(r["commit_ref_rows"] or 0),
            "tag_ref_rows": int(r["tag_ref_rows"] or 0),
            "release_ref_rows": int(r["release_ref_rows"] or 0),
            "sample_cve": r["sample_cve"],
        }

    conn.close()
    return out


def write_csv(path: Path, rows: Iterable[Dict[str, Any]], fields: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()

        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def cache_status(meta: Optional[Dict[str, Any]]) -> str:
    if not meta:
        return "no_cache"

    has_tags = bool(meta.get("has_tags_cache"))
    has_releases = bool(meta.get("has_releases_cache"))

    if has_tags and has_releases:
        return "has_tags_and_releases"
    if has_tags and not has_releases:
        return "has_tags_only"
    if has_releases and not has_tags:
        return "has_releases_only"

    return "no_cache"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--git-dir", required=True)
    ap.add_argument("--cache-dir", required=True)
    ap.add_argument("--out-dir", default="workspace/ref_repo_fetch_targets")
    ap.add_argument(
        "--include-db-ref-not-in-git",
        action="store_true",
        help="기본은 git 폴더에도 있는 direct-ref repo만 대상으로 함. 이 옵션을 주면 DB direct-ref repo도 포함.",
    )
    ap.add_argument(
        "--fetch-missing-kind",
        choices=["none", "any_missing", "no_cache"],
        default="any_missing",
        help=(
            "missing fetch target 기준. "
            "any_missing=tags 또는 releases 중 하나라도 없으면 fetch 대상. "
            "no_cache=tags/releases 파일이 둘 다 없을 때만 fetch 대상."
        ),
    )
    args = ap.parse_args()

    db_path = Path(args.db).resolve()
    git_dir = Path(args.git_dir).resolve()
    cache_dir = Path(args.cache_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[1/4] load git repos")
    git_repo_sources = load_git_repos(git_dir)
    git_repos = set(git_repo_sources.keys())

    print("[2/4] load DB cve_github_refs repos")
    db_ref_meta = load_db_ref_repos(db_path)
    db_ref_repos = set(db_ref_meta.keys())

    print("[3/4] load github_cache repos")
    cache_meta = load_cache_repos(cache_dir)
    cache_repos = set(cache_meta.keys())

    print("[4/4] compare")

    # 핵심 정책:
    # 기본 target = git 폴더에 있고, DB cve_github_refs에도 있는 repo
    if args.include_db_ref_not_in_git:
        target_repos = db_ref_repos
    else:
        target_repos = git_repos & db_ref_repos

    git_not_searchable = git_repos - db_ref_repos
    db_ref_not_in_git = db_ref_repos - git_repos

    all_rows = []
    fetch_rows = []

    for rk in sorted(target_repos):
        dbm = db_ref_meta[rk]
        cm = cache_meta.get(rk)

        status = cache_status(cm)

        tags_count = cm.get("tags_file_count", 0) if cm else 0
        releases_count = cm.get("releases_file_count", 0) if cm else 0

        needs_fetch = False

        if args.fetch_missing_kind == "any_missing":
            needs_fetch = tags_count == 0 or releases_count == 0
        elif args.fetch_missing_kind == "no_cache":
            needs_fetch = tags_count == 0 and releases_count == 0
        elif args.fetch_missing_kind == "none":
            needs_fetch = False

        row = {
            "repo_key": rk,
            "needs_fetch": int(needs_fetch),
            "cache_status": status,
            "cve_count": dbm.get("cve_count", 0),
            "ref_rows": dbm.get("ref_rows", 0),
            "commit_ref_rows": dbm.get("commit_ref_rows", 0),
            "tag_ref_rows": dbm.get("tag_ref_rows", 0),
            "release_ref_rows": dbm.get("release_ref_rows", 0),
            "sample_cve": dbm.get("sample_cve", ""),
            "tags_file_count": tags_count,
            "releases_file_count": releases_count,
            "tags_bytes": cm.get("tags_bytes", 0) if cm else 0,
            "releases_bytes": cm.get("releases_bytes", 0) if cm else 0,
            "git_source_files": ";".join(sorted(git_repo_sources.get(rk, []))),
        }

        all_rows.append(row)

        if needs_fetch:
            fetch_rows.append(row)

    # fetch_missing_github_cache.py가 그대로 읽을 수 있는 최소 CSV
    write_csv(
        out_dir / "fetch_targets_missing_cache.csv",
        fetch_rows,
        [
            "repo_key",
            "needs_fetch",
            "cache_status",
            "cve_count",
            "ref_rows",
            "commit_ref_rows",
            "tag_ref_rows",
            "release_ref_rows",
            "sample_cve",
            "tags_file_count",
            "releases_file_count",
            "tags_bytes",
            "releases_bytes",
            "git_source_files",
        ],
    )

    # 전체 target 상세
    write_csv(
        out_dir / "fetch_targets_all_searchable.csv",
        all_rows,
        [
            "repo_key",
            "needs_fetch",
            "cache_status",
            "cve_count",
            "ref_rows",
            "commit_ref_rows",
            "tag_ref_rows",
            "release_ref_rows",
            "sample_cve",
            "tags_file_count",
            "releases_file_count",
            "tags_bytes",
            "releases_bytes",
            "git_source_files",
        ],
    )

    # git에는 있지만 direct GitHub ref CVE가 없어서 검색 대상 제외된 repo
    write_csv(
        out_dir / "git_repos_not_searchable_by_ref.csv",
        [
            {
                "repo_key": rk,
                "reason": "not_in_cve_github_refs",
                "git_source_files": ";".join(sorted(git_repo_sources.get(rk, []))),
                "has_cache": int(rk in cache_repos),
            }
            for rk in sorted(git_not_searchable)
        ],
        ["repo_key", "reason", "git_source_files", "has_cache"],
    )

    # DB direct-ref에는 있지만 git 목록에는 없는 repo
    write_csv(
        out_dir / "db_ref_repos_not_in_git.csv",
        [
            {
                "repo_key": rk,
                "reason": "direct_ref_repo_not_in_git_list",
                "cve_count": db_ref_meta[rk].get("cve_count", 0),
                "ref_rows": db_ref_meta[rk].get("ref_rows", 0),
                "has_cache": int(rk in cache_repos),
            }
            for rk in sorted(db_ref_not_in_git)
        ],
        ["repo_key", "reason", "cve_count", "ref_rows", "has_cache"],
    )

    summary = {
        "policy": {
            "meaning": "fetch 대상은 git 목록과 DB cve_github_refs의 교집합. 즉 NVD reference에 GitHub URL이 직접 있는 CVE 검색 가능 repo만 사용.",
            "target_formula": "git_repos ∩ db.cve_github_refs.repo_key",
            "fetch_missing_kind": args.fetch_missing_kind,
            "include_db_ref_not_in_git": args.include_db_ref_not_in_git,
        },
        "input": {
            "db": str(db_path),
            "git_dir": str(git_dir),
            "cache_dir": str(cache_dir),
            "out_dir": str(out_dir),
        },
        "counts": {
            "git_repos_total": len(git_repos),
            "db_direct_ref_repos_total": len(db_ref_repos),
            "cache_repos_total": len(cache_repos),
            "target_searchable_repos": len(target_repos),
            "target_searchable_repos_needing_fetch": len(fetch_rows),
            "target_searchable_repos_already_have_cache": len(target_repos) - len(fetch_rows),
            "git_repos_not_searchable_by_ref": len(git_not_searchable),
            "db_ref_repos_not_in_git": len(db_ref_not_in_git),
        },
        "outputs": {
            "fetch_targets_missing_cache": str(out_dir / "fetch_targets_missing_cache.csv"),
            "fetch_targets_all_searchable": str(out_dir / "fetch_targets_all_searchable.csv"),
            "git_repos_not_searchable_by_ref": str(out_dir / "git_repos_not_searchable_by_ref.csv"),
            "db_ref_repos_not_in_git": str(out_dir / "db_ref_repos_not_in_git.csv"),
        },
    }

    with (out_dir / "fetch_target_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("\n[DONE]")
    print(f"summary: {out_dir / 'fetch_target_summary.json'}")
    print(f"fetch targets: {out_dir / 'fetch_targets_missing_cache.csv'}")
    print(f"all searchable: {out_dir / 'fetch_targets_all_searchable.csv'}")
    print(f"not searchable: {out_dir / 'git_repos_not_searchable_by_ref.csv'}")

    print("\n[SUMMARY]")
    for k, v in summary["counts"].items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
