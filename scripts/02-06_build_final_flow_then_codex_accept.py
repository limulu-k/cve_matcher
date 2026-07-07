#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
02-06_build_final_flow_then_codex_accept.py

단일 실행 최종 빌더.

실행 순서
---------
1) 기존 02-04 flow 그대로 base DB 생성
2) 기존 02-05 flow 그대로 manual_overrides 적용 + affected CVE partial reindex
3) codex_res/accept_list.csv 를 "남은 reject/review 후보 중 추가 accept"로 후처리 적용
4) codex accept affected CVE만 NVD range refresh + GitHub cache reload + partial reindex
5) manual/fix 보조 테이블 prune
6) 최종 DB에는 core 8개 테이블만 유지

최종 core schema
----------------
build_summary
cve_github_refs
cves
github_commits
github_versions
nvd_cpe_ranges
repositories
version_cve_index

주의
----
- codex accept는 repo-wide accept가 아니라 row-level accept다.
- 최종 DB 등록 repo는 반드시 git/ 하위 sample_* 파일의 owner@repo allowlist에 포함되어야 한다.
- redirect/canonical repo row는 canonical_repo_key가 allowlist에 있으면 canonical repo_key로 삽입한다.
- reject_list.csv는 DB에 새로 삽입하지 않고 audit/export 및 conflict guard 용도로만 쓴다.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import shutil
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)

CORE_TABLES = [
    "build_summary",
    "cve_github_refs",
    "cves",
    "github_commits",
    "github_versions",
    "nvd_cpe_ranges",
    "repositories",
    "version_cve_index",
]

AUX_TABLES_TO_PRUNE = [
    "manual_cve_repo_accept_overrides",
    "manual_cve_repo_reject_overrides",
    "manual_fix_deleted_cve_github_refs",
    "manual_fix_inserted_cve_github_refs",
    "manual_keep_cve_repo_ref",
    "manual_product_line_allow",
    "manual_repo_accept_overrides",
]


# ------------------------------------------------------------
# Generic helpers
# ------------------------------------------------------------

def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def norm_repo_key(x: Any) -> str:
    s = str(x or "").strip().lower()
    s = s.replace("/", "@")
    if s.endswith(".git"):
        s = s[:-4]
    s = s.strip("/@")
    return s


def split_repo_key(repo_key: str) -> Tuple[str, str]:
    rk = norm_repo_key(repo_key)
    if "@" not in rk:
        return "", rk
    owner, repo = rk.split("@", 1)
    return owner, repo


def norm_product(x: Any) -> str:
    s = str(x or "").strip().lower()
    for a, b in [("-", "_"), (".", "_"), (" ", "_")]:
        s = s.replace(a, b)
    while "__" in s:
        s = s.replace("__", "_")
    return s.strip("_")


def get_first(row: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def row_reason(row: Dict[str, Any]) -> str:
    return get_first(
        row,
        "decision_reason",
        "manual_reason",
        "recommended_reason_by_repo",
        "audit_reason",
        "reject_reason_final",
        "input_reject_reason",
        "reason",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path, required: bool = False) -> List[Dict[str, str]]:
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return [{k: (v if v is not None else "") for k, v in row.items()} for row in reader]


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: Optional[List[str]] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        seen: List[str] = []
        seen_set: Set[str] = set()
        for row in rows:
            for k in row.keys():
                if k not in seen_set:
                    seen.append(k)
                    seen_set.add(k)
        fieldnames = seen
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def dump_query(conn: sqlite3.Connection, sql: str, out_path: Path, params: Sequence[Any] = ()) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cur = conn.execute(sql, params)
    cols = [d[0] for d in cur.description]
    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        while True:
            rows = cur.fetchmany(10000)
            if not rows:
                break
            for r in rows:
                w.writerow([r[c] for c in cols])


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def load_module(path: Path, module_name: str):
    if not path.exists():
        raise FileNotFoundError(path)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------
# GitHub URL/ref helpers
# ------------------------------------------------------------

def ref_kind_from_url(url: str, fallback: str = "") -> Tuple[str, Optional[str], Optional[str]]:
    low = (url or "").lower()
    kind = fallback or ""
    if not kind:
        if "/commit/" in low:
            kind = "commit"
        elif "/releases/tag/" in low:
            kind = "release_tag"
        elif "/tree/" in low:
            kind = "tree"
        elif "/compare/" in low:
            kind = "compare"
        elif "/pull/" in low:
            kind = "pull"
        elif "/issues/" in low:
            kind = "issue"
        else:
            kind = "repo_or_file"

    commit_sha = None
    tag_name = None
    if "/commit/" in low:
        pos = low.find("/commit/") + len("/commit/")
        rest = url[pos:].split("#", 1)[0].split("?", 1)[0].split("/", 1)[0]
        if rest:
            commit_sha = rest[:40]
    if "/releases/tag/" in low:
        pos = low.find("/releases/tag/") + len("/releases/tag/")
        tag_name = url[pos:].split("#", 1)[0].split("?", 1)[0].split("/", 1)[0]
    return kind, commit_sha, tag_name


def github_url_for_accept_row(row: Dict[str, Any], repo_key: str) -> str:
    """Choose URL to store for accepted row.

    If canonical repo_key is used and a normalized/final GitHub URL exists, prefer it.
    Otherwise keep original github_url so evidence is not lost.
    """
    original = get_first(row, "github_url")
    normalized = get_first(row, "normalized_or_suggested_github_url", "url_final_url")
    canonical = norm_repo_key(get_first(row, "canonical_repo_key"))
    if canonical and canonical == repo_key and normalized.lower().startswith("http"):
        return normalized
    return original or normalized


# ------------------------------------------------------------
# Existing flow: 02-04 and 02-05, called in-process
# ------------------------------------------------------------

def make_builder_args(args: argparse.Namespace, git_allowlist: Set[str], git_sample_sources: Dict[str, List[str]]) -> argparse.Namespace:
    bargs = argparse.Namespace()
    bargs.nvd_input = str(args.nvd_input)
    bargs.github_cache = str(args.github_cache)
    bargs.git_dir = str(args.git_dir) if args.git_dir else None
    bargs.git_list = [str(p) for p in args.git_list]
    bargs.out_workspace = str(args.out_workspace)
    bargs.out_db_name = args.out_db_name
    bargs.force = args.force
    bargs.write_csv = False
    bargs.write_audit = args.write_audit
    bargs.max_rejected_audit_rows = args.max_rejected_audit_rows
    bargs.max_review_audit_rows = args.max_review_audit_rows
    bargs.insert_review = args.insert_review
    bargs.skip_version_index = False

    bargs.alpha_owner = args.alpha_owner
    bargs.alpha_repo = args.alpha_repo
    bargs.threshold = args.threshold
    bargs.borderline_threshold = args.borderline_threshold
    bargs.repo_exact_accept_threshold = args.repo_exact_accept_threshold
    bargs.qualifier_score_threshold = args.qualifier_score_threshold
    bargs.qualifier_owner_accept_threshold = args.qualifier_owner_accept_threshold
    bargs.soft_review_threshold = args.soft_review_threshold
    bargs.repo_borderline_min = args.repo_borderline_min
    bargs.owner_weight = args.owner_weight
    bargs.ngram = args.ngram
    bargs.compact_mode = args.compact_mode
    bargs.allow_soft_hard = args.allow_soft_hard
    bargs.recheck_range_repo_score_for_index = not args.no_recheck_range_repo_score_for_index

    bargs.git_allowlist = git_allowlist
    bargs.git_sample_sources = git_sample_sources
    return bargs


def build_base_db_0204(builder, args: argparse.Namespace, out_dir: Path, out_db: Path, git_allowlist: Set[str], git_sample_sources: Dict[str, List[str]]) -> Counter:
    if out_db.exists():
        if args.force:
            out_db.unlink()
        else:
            raise RuntimeError(f"output DB exists: {out_db}. use --force")
    for suffix in ("-wal", "-shm"):
        p = Path(str(out_db) + suffix)
        if p.exists() and args.force:
            p.unlink()

    bargs = make_builder_args(args, git_allowlist, git_sample_sources)
    conn = builder.connect_db(out_db)
    builder.setup_db(conn)

    print("[FLOW 1/5] 02-04 base build: parse NVD and score candidates")
    nvd_stats = builder.build_from_nvd(conn, args.nvd_input, bargs, out_dir)

    print("[FLOW 1/5] 02-04 base build: load GitHub cache")
    cache_stats = builder.load_github_cache(conn, args.github_cache)

    print("[FLOW 1/5] 02-04 base build: build version index")
    index_stats = builder.build_version_index(conn, bargs)

    summary: Dict[str, Any] = {}
    summary.update({f"nvd:{k}": v for k, v in nvd_stats.items()})
    summary.update({f"cache:{k}": v for k, v in cache_stats.items()})
    summary.update({f"index:{k}": v for k, v in index_stats.items()})
    summary.update({
        "policy": "02-04 original flow. CPE/version filtered NVD records. GitHub candidates selected from ref -> cpe -> description. git sample allowlist enforced before insertion.",
        "schema": "same_as_02_01_refonly_builder",
        "nvd_input": str(args.nvd_input),
        "github_cache": str(args.github_cache),
        "git_dir": str(args.git_dir) if args.git_dir else None,
        "git_sample_allowlist_repo_count": len(git_allowlist),
        "out_db": str(out_db),
        "out_workspace": str(out_dir),
        "params": {
            "alpha_owner": args.alpha_owner,
            "alpha_repo": args.alpha_repo,
            "threshold": args.threshold,
            "borderline_threshold": args.borderline_threshold,
            "repo_exact_accept_threshold": args.repo_exact_accept_threshold,
            "qualifier_score_threshold": args.qualifier_score_threshold,
            "qualifier_owner_accept_threshold": args.qualifier_owner_accept_threshold,
            "soft_review_threshold": args.soft_review_threshold,
            "repo_borderline_min": args.repo_borderline_min,
            "owner_weight": args.owner_weight,
            "ngram": args.ngram,
            "compact_mode": args.compact_mode,
            "allow_soft_hard": args.allow_soft_hard,
            "insert_review": args.insert_review,
            "recheck_range_repo_score_for_index": bargs.recheck_range_repo_score_for_index,
        },
    })
    builder.write_summary(conn, out_dir, summary)
    conn.close()

    stats = Counter()
    stats.update({f"nvd:{k}": v for k, v in nvd_stats.items()})
    stats.update({f"cache:{k}": v for k, v in cache_stats.items()})
    stats.update({f"index:{k}": v for k, v in index_stats.items()})
    return stats


def apply_manual_overrides_0205(override, builder, args: argparse.Namespace, out_db: Path, export_dir: Path) -> Counter:
    if not args.manual_overrides_dir.exists():
        print(f"[FLOW 2/5] skip 02-05 manual overrides; missing: {args.manual_overrides_dir}")
        return Counter({"skipped_missing_manual_overrides_dir": 1})

    print("[FLOW 2/5] 02-05 manual_overrides: load CSVs")
    repo_accept_rows, row_accept_rows, row_reject_rows, load_stats = override.load_override_rows(args.manual_overrides_dir)
    print(json.dumps(dict(load_stats), indent=2, ensure_ascii=False))

    conn = sqlite3.connect(str(out_db))
    conn.row_factory = sqlite3.Row
    try:
        print("[FLOW 2/5] 02-05 manual_overrides: apply overrides")
        conn.execute("BEGIN")
        patch_stats = override.apply_overrides(conn, repo_accept_rows, row_accept_rows, row_reject_rows)
        conn.commit()
        print(json.dumps(dict(patch_stats), indent=2, ensure_ascii=False))

        affected = override.affected_cves_from_db(conn)
        print(f"[FLOW 2/5] affected_cves={len(affected)}")

        range_stats = Counter()
        if args.refresh_affected_ranges:
            print("[FLOW 2/5] refresh affected NVD ranges")
            conn.execute("BEGIN")
            range_stats = override.refresh_nvd_ranges_for_cves(conn, builder, args.nvd_input, affected)
            conn.commit()
            print(json.dumps(dict(range_stats), indent=2, ensure_ascii=False))

        cache_stats = Counter()
        if not args.skip_cache_reload_after_manual:
            print("[FLOW 2/5] reload GitHub cache after manual overrides")
            cache_stats = builder.load_github_cache(conn, args.github_cache)
            print(json.dumps(dict(cache_stats), indent=2, ensure_ascii=False))

        reindex_stats = Counter()
        if not args.skip_manual_reindex:
            print("[FLOW 2/5] partial reindex manual affected CVEs")
            conn.execute("BEGIN")
            reindex_stats = override.partial_reindex(conn, builder, affected)
            conn.commit()
            print(json.dumps(dict(reindex_stats), indent=2, ensure_ascii=False))

        summary = {
            "applied_at": now(),
            "phase": "legacy_02_05_manual_overrides",
            "db": str(out_db),
            "csv_dir": str(args.manual_overrides_dir),
            "load_stats": dict(load_stats),
            "patch_stats": dict(patch_stats),
            "range_stats": dict(range_stats),
            "cache_stats": dict(cache_stats),
            "reindex_stats": dict(reindex_stats),
            "affected_cves": sorted(affected),
        }
        conn.execute(
            "INSERT OR REPLACE INTO build_summary(key, value) VALUES (?, ?)",
            ("manual_override:apply_and_partial_reindex", json.dumps(summary, ensure_ascii=False, sort_keys=True)),
        )
        conn.commit()

        print("[FLOW 2/5] export manual override verification CSVs")
        override.export_results(conn, export_dir, affected)
        with (export_dir / "manual_override_apply_summary.json").open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, sort_keys=True)

        stats = Counter()
        stats.update({f"load:{k}": v for k, v in load_stats.items()})
        stats.update({f"patch:{k}": v for k, v in patch_stats.items()})
        stats.update({f"range:{k}": v for k, v in range_stats.items()})
        stats.update({f"cache:{k}": v for k, v in cache_stats.items()})
        stats.update({f"reindex:{k}": v for k, v in reindex_stats.items()})
        stats["affected_cves"] = len(affected)
        return stats
    finally:
        conn.close()


# ------------------------------------------------------------
# Codex accept-after-flow phase
# ------------------------------------------------------------

def choose_accept_repo_key(row: Dict[str, str], git_allowlist: Set[str]) -> Tuple[str, str, str]:
    """Return chosen repo_key, basis, skip_reason.

    Priority:
    1) canonical_repo_key if present and allowlisted
    2) original repo_key if allowlisted
    3) canonical_repo_key even if original row repo redirects? only if allowlisted
    otherwise skip.
    """
    original = norm_repo_key(get_first(row, "repo_key"))
    canonical = norm_repo_key(get_first(row, "canonical_repo_key"))

    if canonical and canonical in git_allowlist:
        return canonical, "canonical_repo_key_in_git_allowlist", ""
    if original and original in git_allowlist:
        return original, "repo_key_in_git_allowlist", ""
    if canonical:
        return "", "", f"repo_not_in_git_allowlist: original={original or '-'} canonical={canonical}"
    return "", "", f"repo_not_in_git_allowlist: original={original or '-'}"


def normalized_accept_key(row: Dict[str, str], repo_key: str, github_url: str) -> Tuple[str, str, str, str, str]:
    return (
        get_first(row, "cve_id").upper(),
        norm_product(get_first(row, "vendor")),
        norm_product(get_first(row, "product")),
        norm_repo_key(repo_key),
        github_url.strip(),
    )


def build_reject_key_set(reject_rows: List[Dict[str, str]]) -> Set[Tuple[str, str, str, str, str]]:
    out: Set[Tuple[str, str, str, str, str]] = set()
    for row in reject_rows:
        decision = get_first(row, "codex_decision", "manual_suggested_action", "suggested_action").lower()
        if decision == "accept":
            continue
        rk = norm_repo_key(get_first(row, "repo_key"))
        url = get_first(row, "normalized_or_suggested_github_url", "github_url") or get_first(row, "github_url")
        out.add(normalized_accept_key(row, rk, url))
        # Also add original URL variant.
        orig_url = get_first(row, "github_url")
        if orig_url and orig_url != url:
            out.add(normalized_accept_key(row, rk, orig_url))
    return out


def ensure_cves_and_refresh_ranges_for_cves(conn: sqlite3.Connection, builder, nvd_input: Path, affected: Set[str]) -> Counter:
    stats = Counter()
    if not affected:
        return stats

    qmarks = ",".join("?" for _ in affected)
    conn.execute(f"DELETE FROM nvd_cpe_ranges WHERE cve_id IN ({qmarks})", sorted(affected))

    cve_insert = """
        INSERT OR REPLACE INTO cves
        (cve_id, published, last_modified, vuln_status, description)
        VALUES (?, ?, ?, ?, ?)
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

    seen_ranges: Set[Tuple[Any, ...]] = set()
    for cve, raw in builder.iter_nvd_records(nvd_input):
        cve_id = builder.extract_cve_id(cve, raw)
        if not cve_id or cve_id.upper() not in affected:
            continue
        cve_id = cve_id.upper()
        stats["nvd_target_records_seen"] += 1
        conn.execute(
            cve_insert,
            (
                cve_id,
                cve.get("published") or raw.get("publishedDate"),
                cve.get("lastModified") or raw.get("lastModifiedDate"),
                cve.get("vulnStatus"),
                builder.extract_description(cve),
            ),
        )
        stats["cves_inserted_or_replaced"] += 1

        for row in builder.make_cpe_range_rows(cve_id, cve, raw):
            if not builder.cpe_range_has_version_info(row):
                stats["range_skip_no_version_info"] += 1
                continue
            key = (
                row.get("cve_id"), row.get("cpe_uri"), row.get("version_start_including"),
                row.get("version_start_excluding"), row.get("version_end_including"),
                row.get("version_end_excluding"), row.get("match_criteria_id"),
            )
            if key in seen_ranges:
                continue
            seen_ranges.add(key)
            conn.execute(
                range_insert,
                (
                    row["cve_id"], row["cpe_uri"], row["part"], row["vendor"], row["product"], row["cpe_version"],
                    row["version_start_including"], row["version_start_excluding"],
                    row["version_end_including"], row["version_end_excluding"],
                    row["vulnerable"], row["match_criteria_id"], row["raw_json"],
                ),
            )
            stats["ranges_inserted"] += 1
    return stats


def insert_codex_accept_row(conn: sqlite3.Connection, override, row: Dict[str, str], chosen_repo_key: str, chosen_url: str, source_prefix: str) -> None:
    row2 = dict(row)
    row2["repo_key"] = chosen_repo_key
    row2["github_url"] = chosen_url
    row2["_override_source_file"] = get_first(row, "source_file") or "codex_res/accept_list.csv"
    row2["reason"] = row_reason(row) or "codex_res accept after legacy flow"
    override.insert_ref_row(conn, row2, source_prefix=source_prefix)


def apply_codex_accept_after_flow(
    conn: sqlite3.Connection,
    builder,
    override,
    args: argparse.Namespace,
    git_allowlist: Set[str],
    export_dir: Path,
) -> Counter:
    stats = Counter()
    export_dir.mkdir(parents=True, exist_ok=True)

    accept_path = args.codex_res_dir / args.accept_filename
    reject_path = args.codex_res_dir / args.reject_filename
    accept_rows = read_csv(accept_path, required=args.require_codex_accept)
    reject_rows = read_csv(reject_path, required=False)

    stats["accept_csv_rows"] = len(accept_rows)
    stats["reject_csv_rows"] = len(reject_rows)
    if accept_path.exists():
        stats["accept_csv_sha256"] = sha256_file(accept_path)
    if reject_path.exists():
        stats["reject_csv_sha256"] = sha256_file(reject_path)

    reject_key_set = build_reject_key_set(reject_rows)

    applied_rows: List[Dict[str, Any]] = []
    skipped_rows: List[Dict[str, Any]] = []
    conflict_rows: List[Dict[str, Any]] = []
    normalized_reject_export: List[Dict[str, Any]] = []

    for row in reject_rows:
        rk = norm_repo_key(get_first(row, "repo_key"))
        normalized_reject_export.append({
            **row,
            "normalized_repo_key": rk,
            "normalized_vendor": norm_product(get_first(row, "vendor")),
            "normalized_product": norm_product(get_first(row, "product")),
            "normalized_cve_id": get_first(row, "cve_id").upper(),
            "export_note": "audit_only_not_inserted_to_final_db",
        })

    override.setup_manual_tables(conn)

    affected: Set[str] = set()
    seen_accept_keys: Set[Tuple[str, str, str, str, str]] = set()

    for idx, row in enumerate(accept_rows, 1):
        cve_id = get_first(row, "cve_id").upper()
        decision = get_first(row, "codex_decision", "manual_suggested_action", "suggested_action").lower()
        if decision and decision != "accept":
            stats["skip_not_accept_decision"] += 1
            skipped_rows.append({**row, "skip_reason": f"codex_decision_not_accept:{decision}", "input_row_number": idx})
            continue
        if not cve_id:
            stats["skip_no_cve_id"] += 1
            skipped_rows.append({**row, "skip_reason": "missing_cve_id", "input_row_number": idx})
            continue

        chosen_repo_key, repo_basis, skip_reason = choose_accept_repo_key(row, git_allowlist)
        if skip_reason:
            stats["skip_repo_not_in_git_allowlist"] += 1
            skipped_rows.append({**row, "skip_reason": skip_reason, "input_row_number": idx})
            continue

        chosen_url = github_url_for_accept_row(row, chosen_repo_key)
        if not chosen_url:
            stats["skip_no_github_url"] += 1
            skipped_rows.append({**row, "skip_reason": "missing_github_url", "chosen_repo_key": chosen_repo_key, "input_row_number": idx})
            continue

        key = normalized_accept_key(row, chosen_repo_key, chosen_url)
        if key in seen_accept_keys:
            stats["skip_duplicate_accept_row"] += 1
            skipped_rows.append({**row, "skip_reason": "duplicate_accept_key", "chosen_repo_key": chosen_repo_key, "chosen_github_url": chosen_url, "input_row_number": idx})
            continue
        seen_accept_keys.add(key)

        # Conflict guard: exact same normalized product/repo/url is in reject list.
        if key in reject_key_set:
            stats["conflict_accept_vs_reject_exact"] += 1
            conflict_rows.append({**row, "conflict_reason": "same_normalized_cve_vendor_product_repo_url_in_reject_list", "chosen_repo_key": chosen_repo_key, "chosen_github_url": chosen_url, "input_row_number": idx})
            if args.skip_conflicting_codex_accept:
                skipped_rows.append({**row, "skip_reason": "conflict_with_reject_list", "chosen_repo_key": chosen_repo_key, "chosen_github_url": chosen_url, "input_row_number": idx})
                continue

        before_ref = conn.execute(
            "SELECT 1 FROM cve_github_refs WHERE cve_id=? AND repo_key=? AND github_url=?",
            (cve_id, chosen_repo_key, chosen_url),
        ).fetchone() is not None

        insert_codex_accept_row(conn, override, row, chosen_repo_key, chosen_url, "codex_accept_after_02_05")
        affected.add(cve_id)
        stats["codex_accept_refs_insert_or_replace"] += 1
        if before_ref:
            stats["codex_accept_existing_ref_replaced_or_kept"] += 1
        else:
            stats["codex_accept_new_ref"] += 1

        applied_rows.append({
            **row,
            "input_row_number": idx,
            "chosen_repo_key": chosen_repo_key,
            "chosen_github_url": chosen_url,
            "repo_choice_basis": repo_basis,
            "already_existed_before_insert": int(before_ref),
            "applied_source": "codex_accept_after_02_05",
        })

    conn.commit()

    print(f"[FLOW 3/5] codex accept rows applied={len(applied_rows)} skipped={len(skipped_rows)} conflicts={len(conflict_rows)} affected_cves={len(affected)}")

    range_stats = Counter()
    if affected:
        print("[FLOW 3/5] refresh NVD cves/ranges for codex affected CVEs")
        conn.execute("BEGIN")
        range_stats = ensure_cves_and_refresh_ranges_for_cves(conn, builder, args.nvd_input, affected)
        conn.commit()
        print(json.dumps(dict(range_stats), indent=2, ensure_ascii=False))

    cache_stats = Counter()
    if affected and not args.skip_cache_reload_after_codex:
        print("[FLOW 3/5] reload GitHub cache after codex accepts")
        cache_stats = builder.load_github_cache(conn, args.github_cache)
        print(json.dumps(dict(cache_stats), indent=2, ensure_ascii=False))

    reindex_stats = Counter()
    if affected and not args.skip_codex_reindex:
        print("[FLOW 3/5] partial reindex codex affected CVEs")
        conn.execute("BEGIN")
        reindex_stats = override.partial_reindex(conn, builder, affected)
        conn.commit()
        print(json.dumps(dict(reindex_stats), indent=2, ensure_ascii=False))

    # Export analysis CSVs requested by user.
    write_csv(export_dir / "codex_accept_applied.csv", applied_rows)
    write_csv(export_dir / "codex_accept_skipped.csv", skipped_rows)
    write_csv(export_dir / "codex_accept_conflicts.csv", conflict_rows)
    write_csv(export_dir / "codex_reject_audit_only.csv", normalized_reject_export)

    if affected:
        qmarks = ",".join("?" for _ in affected)
        params = sorted(affected)
        dump_query(
            conn,
            f"SELECT * FROM cve_github_refs WHERE cve_id IN ({qmarks}) ORDER BY cve_id, repo_key, github_url",
            export_dir / "codex_affected_cve_github_refs.csv",
            params,
        )
        dump_query(
            conn,
            f"SELECT * FROM version_cve_index WHERE cve_id IN ({qmarks}) ORDER BY cve_id, repo_key, version_raw",
            export_dir / "codex_affected_version_cve_index.csv",
            params,
        )

    summary = {
        "applied_at": now(),
        "phase": "codex_accept_after_legacy_02_05",
        "codex_res_dir": str(args.codex_res_dir),
        "accept_path": str(accept_path),
        "reject_path": str(reject_path),
        "stats": dict(stats),
        "range_stats": dict(range_stats),
        "cache_stats": dict(cache_stats),
        "reindex_stats": dict(reindex_stats),
        "affected_cves": sorted(affected),
        "notes": [
            "codex accept is applied after original 02-04 and 02-05 flow",
            "repo registration is restricted to git sample allowlist",
            "accept is row-level: CVE + repo_key + product/range guarded by manual_product_line_allow",
            "reject_list is exported as audit only and used for exact conflict detection, not inserted into final DB",
        ],
    }
    with (export_dir / "codex_accept_apply_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, sort_keys=True)
    conn.execute(
        "INSERT OR REPLACE INTO build_summary(key, value) VALUES (?, ?)",
        ("codex_accept:apply_after_02_05", json.dumps(summary, ensure_ascii=False, sort_keys=True)),
    )
    conn.commit()

    out_stats = Counter(stats)
    out_stats.update({f"range:{k}": v for k, v in range_stats.items()})
    out_stats.update({f"cache:{k}": v for k, v in cache_stats.items()})
    out_stats.update({f"reindex:{k}": v for k, v in reindex_stats.items()})
    out_stats["affected_cves"] = len(affected)
    out_stats["applied_rows"] = len(applied_rows)
    out_stats["skipped_rows"] = len(skipped_rows)
    out_stats["conflict_rows"] = len(conflict_rows)
    return out_stats


# ------------------------------------------------------------
# Final prune/validation
# ------------------------------------------------------------

def prune_aux_tables(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("BEGIN")
    try:
        for t in AUX_TABLES_TO_PRUNE:
            conn.execute(f"DROP TABLE IF EXISTS {q(t)}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    conn.execute("VACUUM")


def validate_core_schema(conn: sqlite3.Connection) -> List[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = [str(r["name"] if isinstance(r, sqlite3.Row) else r[0]) for r in rows]
    expected = sorted(CORE_TABLES)
    if tables != expected:
        raise RuntimeError(f"unexpected final tables. expected={expected}, actual={tables}")
    qc = conn.execute("PRAGMA quick_check").fetchone()[0]
    if qc != "ok":
        raise RuntimeError(f"SQLite quick_check failed: {qc}")
    return tables


def write_final_summary(conn: sqlite3.Connection, out_dir: Path, meta: Dict[str, Any]) -> None:
    counts: Dict[str, int] = {}
    for table in CORE_TABLES:
        counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {q(table)}").fetchone()[0])
        conn.execute(
            "INSERT OR REPLACE INTO build_summary(key, value) VALUES (?, ?)",
            (f"rows:{table}", json.dumps(counts[table], ensure_ascii=False)),
        )
    meta["final_counts"] = counts
    meta["final_tables"] = sorted(CORE_TABLES)
    with (out_dir / "build_summary.json").open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False, sort_keys=True)
    for k, v in meta.items():
        conn.execute(
            "INSERT OR REPLACE INTO build_summary(key, value) VALUES (?, ?)",
            (f"final:{k}", json.dumps(v, ensure_ascii=False, sort_keys=True)),
        )
    conn.commit()


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Build final CVE-version DB by legacy 02-04/02-05 flow, then apply codex_res accept_list.")
    ap.add_argument("--nvd-input", default="./data/filtered.json", type=Path)
    ap.add_argument("--github-cache", default="./workspace/github_cache", type=Path)
    ap.add_argument("--git-dir", default="./git", type=Path)
    ap.add_argument("--git-list", action="append", default=[], type=Path)
    ap.add_argument("--manual-overrides-dir", default="./manual_overrides", type=Path)
    ap.add_argument("--codex-res-dir", default="./codex_res", type=Path)
    ap.add_argument("--accept-filename", default="accept_list.csv")
    ap.add_argument("--reject-filename", default="reject_list.csv")
    ap.add_argument("--builder-script", default="./scripts/02-04_refilteringNbuild_nvd2db.py", type=Path)
    ap.add_argument("--override-script", default="./scripts/02-05_apply_manual_overrides_and_partial_reindex.py", type=Path)
    ap.add_argument("--out-workspace", default="./workspace_refiltered_v2_final", type=Path)
    ap.add_argument("--out-db-name", default="version_cve_refiltered.db")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--backup-existing", action="store_true")
    ap.add_argument("--write-audit", action="store_true", default=True)
    ap.add_argument("--max-rejected-audit-rows", type=int, default=200000)
    ap.add_argument("--max-review-audit-rows", type=int, default=200000)
    ap.add_argument("--insert-review", action="store_true")

    # 02-04 scoring params, defaults copied from original script.
    ap.add_argument("--alpha-owner", type=float, default=0.8)
    ap.add_argument("--alpha-repo", type=float, default=0.5)
    ap.add_argument("--threshold", type=float, default=0.90)
    ap.add_argument("--borderline-threshold", type=float, default=0.88)
    ap.add_argument("--repo-exact-accept-threshold", type=float, default=0.98)
    ap.add_argument("--qualifier-score-threshold", type=float, default=0.90)
    ap.add_argument("--qualifier-owner-accept-threshold", type=float, default=0.90)
    ap.add_argument("--soft-review-threshold", type=float, default=0.90)
    ap.add_argument("--repo-borderline-min", type=float, default=0.84)
    ap.add_argument("--owner-weight", type=float, default=0.35)
    ap.add_argument("--ngram", type=int, default=2)
    ap.add_argument("--compact-mode", choices=["sorted", "original", "both_max"], default="sorted")
    ap.add_argument("--allow-soft-hard", action="store_true")
    ap.add_argument("--no-recheck-range-repo-score-for-index", action="store_true")

    # Flow controls.
    ap.add_argument("--refresh-affected-ranges", action="store_true", default=True)
    ap.add_argument("--skip-cache-reload-after-manual", action="store_true")
    ap.add_argument("--skip-manual-reindex", action="store_true")
    ap.add_argument("--skip-cache-reload-after-codex", action="store_true")
    ap.add_argument("--skip-codex-reindex", action="store_true")
    ap.add_argument("--require-codex-accept", action="store_true", default=True)
    ap.add_argument("--skip-conflicting-codex-accept", action="store_true", help="If an exact accept row also appears in reject_list, skip it instead of applying and flagging conflict.")
    args = ap.parse_args()

    args.nvd_input = args.nvd_input.resolve()
    args.github_cache = args.github_cache.resolve()
    args.git_dir = args.git_dir.resolve() if args.git_dir else None
    args.git_list = [p.resolve() for p in args.git_list]
    args.manual_overrides_dir = args.manual_overrides_dir.resolve()
    args.codex_res_dir = args.codex_res_dir.resolve()
    args.builder_script = args.builder_script.resolve()
    args.override_script = args.override_script.resolve()
    args.out_workspace = args.out_workspace.resolve()
    return args


def validate_inputs(args: argparse.Namespace) -> None:
    for name in ["nvd_input", "github_cache", "builder_script", "override_script", "codex_res_dir"]:
        p = getattr(args, name)
        if not p.exists():
            raise FileNotFoundError(f"missing --{name.replace('_', '-')}: {p}")
    if args.git_dir and not args.git_dir.exists():
        raise FileNotFoundError(f"missing --git-dir: {args.git_dir}")
    if args.require_codex_accept and not (args.codex_res_dir / args.accept_filename).exists():
        raise FileNotFoundError(f"missing codex accept list: {args.codex_res_dir / args.accept_filename}")


def main() -> int:
    args = parse_args()
    validate_inputs(args)

    out_dir = args.out_workspace
    out_dir.mkdir(parents=True, exist_ok=True)
    out_db = out_dir / args.out_db_name
    export_dir = out_dir / "codex_res_exports"
    manual_export_dir = out_dir / "manual_override_exports"

    log_meta: Dict[str, Any] = {
        "started_at": now(),
        "nvd_input": str(args.nvd_input),
        "github_cache": str(args.github_cache),
        "git_dir": str(args.git_dir) if args.git_dir else None,
        "manual_overrides_dir": str(args.manual_overrides_dir),
        "codex_res_dir": str(args.codex_res_dir),
        "builder_script": str(args.builder_script),
        "override_script": str(args.override_script),
        "out_db": str(out_db),
        "flow": [
            "02-04 base build",
            "02-05 manual overrides and partial reindex",
            "codex_res accept_list applied after existing flow",
            "codex affected partial reindex",
            "manual/fix auxiliary table prune",
            "core schema validation",
        ],
    }

    if out_db.exists() and args.backup_existing:
        backup = out_db.with_suffix(out_db.suffix + f".bak_before_0206_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        shutil.copy2(out_db, backup)
        print(f"[BACKUP] {backup}")

    builder = load_module(args.builder_script, "builder0204_single_flow")
    override = load_module(args.override_script, "override0205_single_flow")

    git_sample_sources_raw = builder.load_git_sample_allowlist(args.git_dir, args.git_list)
    git_allowlist: Set[str] = set(git_sample_sources_raw.keys())
    git_sample_sources: Dict[str, List[str]] = {rk: sorted(srcs) for rk, srcs in git_sample_sources_raw.items()}
    if not git_allowlist:
        raise RuntimeError("git allowlist is empty. final DB must be restricted to owner@repo list under git/.")

    print(f"[START] {now()}")
    print(f"[INFO] output DB: {out_db}")
    print(f"[INFO] git allowlist repos={len(git_allowlist)}")

    with (out_dir / "git_sample_allowlist.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["repo_key", "source_files"])
        w.writeheader()
        for rk in sorted(git_allowlist):
            w.writerow({"repo_key": rk, "source_files": ";".join(git_sample_sources.get(rk, []))})

    base_stats = build_base_db_0204(builder, args, out_dir, out_db, git_allowlist, git_sample_sources)
    log_meta["base_02_04_stats"] = dict(base_stats)

    manual_stats = apply_manual_overrides_0205(override, builder, args, out_db, manual_export_dir)
    log_meta["legacy_02_05_stats"] = dict(manual_stats)

    conn = sqlite3.connect(str(out_db))
    conn.row_factory = sqlite3.Row
    try:
        codex_stats = apply_codex_accept_after_flow(conn, builder, override, args, git_allowlist, export_dir)
        log_meta["codex_accept_stats"] = dict(codex_stats)

        print("[FLOW 4/5] prune manual/fix auxiliary tables")
        prune_aux_tables(conn)

        print("[FLOW 5/5] validate final core schema")
        final_tables = validate_core_schema(conn)
        print("[OK] final tables:", ", ".join(final_tables))

        log_meta["finished_at"] = now()
        write_final_summary(conn, out_dir, log_meta)

        print("[SUMMARY] final row counts")
        for table in CORE_TABLES:
            n = conn.execute(f"SELECT COUNT(*) FROM {q(table)}").fetchone()[0]
            print(f"{table},{n}")
    finally:
        conn.close()

    print(f"[DONE] DB = {out_db}")
    print(f"[DONE] codex exports = {export_dir}")
    print(f"[DONE] summary = {out_dir / 'build_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
