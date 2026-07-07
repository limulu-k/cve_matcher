#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_manual_overrides_and_partial_reindex.py

목표
----
현재 생성된 version_cve_refiltered.db에 대해 manual override CSV들을 한 번에 적용하고,
영향받은 CVE만 version_cve_index를 부분 재생성한다.

해결하는 문제
--------------
1. CSV마다 컬럼이 달라서 no such column 오류가 나는 문제를 제거한다.
   - CSV를 SQLite 임시 테이블로 넣지 않고 Python DictReader로 읽는다.
   - 누락 컬럼은 get()으로 빈 값 처리한다.

2. 02-04 builder를 importlib로 로드할 때 dataclass 오류가 나는 문제를 제거한다.
   - exec_module 전에 sys.modules[spec.name] = module 등록.

3. product-line contamination을 방지한다.
   - 예: bc-csharp -> bc-java, mongoose_os -> mongoose, jquery_ui -> jquery 등은 reject.
   - 올바른 product-line repo를 manual correct mapping으로 삽입.

입력 파일명 기본값
----------------
manual_overrides/
  metadata_nonproduct_term_boundary_audit_accept.csv
  mismatch_or_review_cve_github_pairs_accept.csv
  mismatch_or_review_cve_github_pairs_reject.csv
  review_inserted_manual_decision_accept.csv
  review_inserted_manual_decision_reject.csv

주의
----
- metadata_nonproduct_term_boundary_audit_accept.csv는 repo-level allow 용도다.
  cve_github_refs에 새 CVE-row를 삽입하지 않는다.
- review_inserted_manual_decision_reject.csv는 이름은 reject지만, codex_decision=accept인 행만 accept로 반영한다.
- partial reindex 전, --nvd-input이 주어지고 --refresh-affected-ranges가 켜져 있으면
  영향받은 CVE의 nvd_cpe_ranges를 NVD 원본에서 다시 채운다.
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


# ------------------------------------------------------------
# Static manual product-line corrections
# ------------------------------------------------------------

MANUAL_CORRECT_REFS = [
    # CVE-2012-6662: jquery_ui -> jquery-ui, not jquery core
    {
        "cve_id": "CVE-2012-6662",
        "vendor": "jqueryui",
        "product": "jquery_ui",
        "repo_key": "jquery@jquery-ui",
        "github_url": "https://github.com/jquery/jquery-ui/commit/5fee6fd5000072ff32f2d65b6451f39af9e0e39e",
        "ref_kind": "commit",
        "commit_sha": "5fee6fd5000072ff32f2d65b6451f39af9e0e39e",
        "source": "manual_fix:correct_product_line",
        "reason": "jquery_ui CPE row must map to jquery/jquery-ui, not jquery/jquery core",
    },
    {
        "cve_id": "CVE-2012-6662",
        "vendor": "jqueryui",
        "product": "jquery_ui",
        "repo_key": "jquery@jquery-ui",
        "github_url": "https://github.com/jquery/jquery-ui/commit/f2854408cce7e4b7fc6bf8676761904af9c96bde",
        "ref_kind": "commit",
        "commit_sha": "f2854408cce7e4b7fc6bf8676761904af9c96bde",
        "source": "manual_fix:correct_product_line",
        "reason": "jquery_ui CPE row must map to jquery/jquery-ui, not jquery/jquery core",
    },

    # CVE-2020-15522: Bouncy Castle product lines
    {
        "cve_id": "CVE-2020-15522",
        "vendor": "bouncycastle",
        "product": "bc-csharp",
        "repo_key": "bcgit@bc-csharp",
        "github_url": "https://github.com/bcgit/bc-csharp/wiki/CVE%E2%80%902020%E2%80%9015522",
        "ref_kind": "repo_or_file",
        "commit_sha": None,
        "source": "manual_fix:correct_product_line",
        "reason": "bc-csharp CPE row must map to bcgit/bc-csharp, not bcgit/bc-java",
    },
    {
        "cve_id": "CVE-2020-15522",
        "vendor": "bouncycastle",
        "product": "bc-java",
        "repo_key": "bcgit@bc-java",
        "github_url": "https://github.com/bcgit/bc-java/wiki/CVE-2020-15522",
        "ref_kind": "repo_or_file",
        "commit_sha": None,
        "source": "manual_fix:correct_product_line",
        "reason": "bc-java CPE row must map to bcgit/bc-java",
    },

    # CVE-2017-7185: mongoose library and mongoose_os must be separated
    {
        "cve_id": "CVE-2017-7185",
        "vendor": "cesanta",
        "product": "mongoose",
        "repo_key": "cesanta@mongoose",
        "github_url": "https://github.com/cesanta/mongoose/commit/b8402ed0733e3f244588b61ad5fedd093e3cf9cc",
        "ref_kind": "commit",
        "commit_sha": "b8402ed0733e3f244588b61ad5fedd093e3cf9cc",
        "source": "manual_fix:correct_product_line",
        "reason": "mongoose library CPE row must map to cesanta/mongoose",
    },
    {
        "cve_id": "CVE-2017-7185",
        "vendor": "cesanta",
        "product": "mongoose_os",
        "repo_key": "cesanta@mongoose-os",
        "github_url": "https://github.com/cesanta/mongoose-os/commit/042eb437973a202d00589b13d628181c6de5cf5b",
        "ref_kind": "commit",
        "commit_sha": "042eb437973a202d00589b13d628181c6de5cf5b",
        "source": "manual_fix:correct_product_line",
        "reason": "mongoose_os CPE row must map to cesanta/mongoose-os, not cesanta/mongoose",
    },

    # CVE-2023-43361: vorbis-tools product line
    {
        "cve_id": "CVE-2023-43361",
        "vendor": "xiph",
        "product": "vorbis-tools",
        "repo_key": "xiph@vorbis-tools",
        "github_url": "https://github.com/xiph/vorbis-tools",
        "ref_kind": "repo_or_file",
        "commit_sha": None,
        "source": "manual_fix:correct_product_line",
        "reason": "vorbis-tools CPE row must map to xiph/vorbis-tools, not xiph/vorbis",
    },
]

# These CVE-repo references are valid for a different product line in the same CVE.
# Therefore reject CSV must not delete cve_github_refs itself; only wrong product range index rows are removed.
MANUAL_KEEP_CVE_REPO_REF = {
    ("CVE-2020-15522", "bcgit@bc-java"): "keep bc-java repo for bc-java product line; reject only bc-csharp -> bc-java contamination",
    ("CVE-2017-7185", "cesanta@mongoose"): "keep mongoose repo for mongoose library product line; reject only mongoose_os -> mongoose contamination",
}


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def norm_repo_key(x: Any) -> str:
    s = str(x or "").strip().lower()
    s = s.replace("/", "@")
    s = s.replace(".git", "")
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
    s = s.replace("-", "_")
    s = s.replace(".", "_")
    s = s.replace(" ", "_")
    while "__" in s:
        s = s.replace("__", "_")
    return s.strip("_")


def get_first(row: Dict[str, str], *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return ""


def row_reason(row: Dict[str, str]) -> str:
    return get_first(
        row,
        "decision_reason",
        "manual_reason",
        "mismatch_reason",
        "recommended_reason_by_repo",
        "audit_reason",
        "reason",
    )


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            rows.append({k: (v if v is not None else "") for k, v in row.items()})
        return rows


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ref_kind_from_url(url: str, fallback: str = "") -> Tuple[str, Optional[str], Optional[str]]:
    low = (url or "").lower()
    if fallback:
        kind = fallback
    elif "/commit/" in low:
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
    return kind, commit_sha, tag_name


def connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def load_builder(script_path: Path):
    if not script_path.exists():
        raise FileNotFoundError(script_path)
    spec = importlib.util.spec_from_file_location("builder0204", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load builder script: {script_path}")
    mod = importlib.util.module_from_spec(spec)
    # Critical for dataclasses in imported script
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------
# Override loading
# ------------------------------------------------------------

def load_override_rows(csv_dir: Path) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], List[Dict[str, str]], Counter]:
    """Return: repo_accept_rows, row_accept_rows, row_reject_rows, stats"""
    stats = Counter()

    files = {
        "metadata_accept": csv_dir / "metadata_nonproduct_term_boundary_audit_accept.csv",
        "mismatch_accept": csv_dir / "mismatch_or_review_cve_github_pairs_accept.csv",
        "mismatch_reject": csv_dir / "mismatch_or_review_cve_github_pairs_reject.csv",
        "review_accept": csv_dir / "review_inserted_manual_decision_accept.csv",
        "review_reject": csv_dir / "review_inserted_manual_decision_reject.csv",
    }

    loaded: Dict[str, List[Dict[str, str]]] = {}
    for name, path in files.items():
        rows = read_csv(path)
        loaded[name] = rows
        stats[f"read:{name}:rows"] = len(rows)
        stats[f"read:{name}:sha256"] = sha256_file(path)

    # Repo-level accept: do not insert refs, just mark repo as accepted for metadata nonproduct boundary audit.
    repo_accept_rows = []
    for row in loaded["metadata_accept"]:
        if get_first(row, "codex_decision").lower() == "reject":
            continue
        if get_first(row, "repo_key"):
            repo_accept_rows.append(row)

    # Row-level accept files.
    row_accept_rows = []
    for src_name in ["mismatch_accept", "review_accept"]:
        for row in loaded[src_name]:
            decision = get_first(row, "codex_decision", "manual_suggested_action", "suggested_action").lower()
            # These are accept files; only explicit reject blocks insertion.
            if decision == "reject":
                continue
            if get_first(row, "cve_id") and get_first(row, "repo_key") and get_first(row, "github_url"):
                row["_override_source_file"] = files[src_name].name
                row_accept_rows.append(row)

    # review_inserted_manual_decision_reject.csv: accept only rows explicitly marked accept.
    for row in loaded["review_reject"]:
        decision = get_first(row, "codex_decision", "manual_suggested_action", "suggested_action").lower()
        if decision == "accept":
            if get_first(row, "cve_id") and get_first(row, "repo_key") and get_first(row, "github_url"):
                row["_override_source_file"] = files["review_reject"].name + ":accept_only"
                row_accept_rows.append(row)

    # Row-level reject file: reject unless explicitly codex_decision=accept.
    row_reject_rows = []
    for row in loaded["mismatch_reject"]:
        decision = get_first(row, "codex_decision", "suggested_action", "manual_suggested_action").lower()
        if decision == "accept":
            continue
        if get_first(row, "cve_id") and get_first(row, "repo_key"):
            row["_override_source_file"] = files["mismatch_reject"].name
            row_reject_rows.append(row)

    stats["repo_accept_rows"] = len(repo_accept_rows)
    stats["row_accept_rows"] = len(row_accept_rows)
    stats["row_reject_rows"] = len(row_reject_rows)
    return repo_accept_rows, row_accept_rows, row_reject_rows, stats


# ------------------------------------------------------------
# DB patch
# ------------------------------------------------------------

def setup_manual_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS manual_repo_accept_overrides (
            repo_key TEXT PRIMARY KEY,
            reason TEXT,
            source_file TEXT,
            raw_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS manual_cve_repo_accept_overrides (
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            repo_key TEXT,
            github_url TEXT,
            reason TEXT,
            source_file TEXT,
            raw_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, repo_key, github_url)
        );

        CREATE TABLE IF NOT EXISTS manual_cve_repo_reject_overrides (
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            repo_key TEXT,
            github_url TEXT,
            reason TEXT,
            source_file TEXT,
            raw_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, product, repo_key, github_url)
        );

        CREATE TABLE IF NOT EXISTS manual_product_line_allow (
            cve_id TEXT NOT NULL,
            repo_key TEXT NOT NULL,
            allowed_product_norm TEXT NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, repo_key, allowed_product_norm)
        );

        CREATE TABLE IF NOT EXISTS manual_keep_cve_repo_ref (
            cve_id TEXT NOT NULL,
            repo_key TEXT NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, repo_key)
        );

        CREATE TABLE IF NOT EXISTS manual_fix_deleted_cve_github_refs AS
        SELECT datetime('now') AS fixed_at, '' AS fix_reason, *
        FROM cve_github_refs
        WHERE 0;

        CREATE TABLE IF NOT EXISTS manual_fix_inserted_cve_github_refs AS
        SELECT datetime('now') AS fixed_at, '' AS fix_reason, *
        FROM cve_github_refs
        WHERE 0;
        """
    )


def insert_repository(conn: sqlite3.Connection, repo_key: str) -> None:
    owner, repo = split_repo_key(repo_key)
    if not owner or not repo:
        return
    conn.execute(
        "INSERT OR IGNORE INTO repositories(repo_key, owner, repo) VALUES (?, ?, ?)",
        (repo_key, owner, repo),
    )


def insert_ref_row(conn: sqlite3.Connection, row: Dict[str, Any], source_prefix: str) -> None:
    cve_id = str(row.get("cve_id") or "").strip().upper()
    repo_key = norm_repo_key(row.get("repo_key"))
    github_url = str(row.get("github_url") or "").strip()
    if not cve_id or not repo_key or not github_url:
        return

    vendor = str(row.get("vendor") or "")
    product = str(row.get("product") or "")
    ref_kind = str(row.get("ref_kind") or "")
    kind, commit_sha, tag_name = ref_kind_from_url(github_url, fallback=ref_kind)
    if row.get("commit_sha"):
        commit_sha = row.get("commit_sha")

    reason = str(row.get("reason") or row_reason(row) or "manual override accept")
    raw_json = json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)
    reference_json = json.dumps(
        {
            "manual_override": source_prefix,
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "repo_key": repo_key,
            "github_url": github_url,
            "reason": reason,
            "raw_row": row,
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    insert_repository(conn, repo_key)
    conn.execute(
        """
        INSERT OR REPLACE INTO cve_github_refs
        (cve_id, repo_key, github_url, ref_kind, commit_sha, tag_name, source, reference_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (cve_id, repo_key, github_url, kind, commit_sha, tag_name, f"manual_override:{source_prefix}", reference_json),
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO manual_cve_repo_accept_overrides
        (cve_id, vendor, product, repo_key, github_url, reason, source_file, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cve_id,
            vendor,
            product,
            repo_key,
            github_url,
            reason,
            str(row.get("_override_source_file") or source_prefix),
            raw_json,
        ),
    )
    if product:
        conn.execute(
            """
            INSERT OR REPLACE INTO manual_product_line_allow
            (cve_id, repo_key, allowed_product_norm, reason)
            VALUES (?, ?, ?, ?)
            """,
            (cve_id, repo_key, norm_product(product), reason),
        )


def log_inserted_refs(conn: sqlite3.Connection, cve_ids: Sequence[str], fix_reason: str) -> None:
    for cve_id in cve_ids:
        conn.execute(
            """
            INSERT INTO manual_fix_inserted_cve_github_refs
            SELECT datetime('now'), ?, r.*
            FROM cve_github_refs r
            WHERE r.cve_id = ?
            """,
            (fix_reason, cve_id),
        )


def apply_overrides(
    conn: sqlite3.Connection,
    repo_accept_rows: List[Dict[str, str]],
    row_accept_rows: List[Dict[str, str]],
    row_reject_rows: List[Dict[str, str]],
) -> Counter:
    stats = Counter()
    setup_manual_tables(conn)

    # repo-level accept overrides
    for row in repo_accept_rows:
        rk = norm_repo_key(get_first(row, "repo_key"))
        if not rk:
            continue
        reason = row_reason(row) or "metadata non-product term boundary accepted"
        conn.execute(
            """
            INSERT OR REPLACE INTO manual_repo_accept_overrides
            (repo_key, reason, source_file, raw_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                rk,
                reason,
                "metadata_nonproduct_term_boundary_audit_accept.csv",
                json.dumps(row, ensure_ascii=False, sort_keys=True),
            ),
        )
        stats["repo_accept_overrides"] += 1

    # Row-level accepts from CSV
    for row in row_accept_rows:
        insert_ref_row(conn, row, source_prefix="accept_csv")
        stats["row_accept_refs_inserted_or_replaced"] += 1

    # Row-level rejects: log and remove version index rows for matching product only.
    reject_products_by_pair: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for row in row_reject_rows:
        cve_id = get_first(row, "cve_id").upper()
        repo_key = norm_repo_key(get_first(row, "repo_key"))
        github_url = get_first(row, "github_url")
        vendor = get_first(row, "vendor")
        product = get_first(row, "product")
        reason = row_reason(row) or "manual override reject"
        raw_json = json.dumps(row, ensure_ascii=False, sort_keys=True)
        if not cve_id or not repo_key:
            continue

        conn.execute(
            """
            INSERT OR REPLACE INTO manual_cve_repo_reject_overrides
            (cve_id, vendor, product, repo_key, github_url, reason, source_file, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                vendor,
                product,
                repo_key,
                github_url,
                reason,
                str(row.get("_override_source_file") or "mismatch_or_review_cve_github_pairs_reject.csv"),
                raw_json,
            ),
        )
        if product:
            reject_products_by_pair[(cve_id, repo_key)].add(norm_product(product))
        stats["row_reject_overrides"] += 1

    # Keep valid cross-product refs.
    for (cve_id, repo_key), reason in MANUAL_KEEP_CVE_REPO_REF.items():
        conn.execute(
            """
            INSERT OR REPLACE INTO manual_keep_cve_repo_ref(cve_id, repo_key, reason)
            VALUES (?, ?, ?)
            """,
            (cve_id, repo_key, reason),
        )

    # Delete version_cve_index rows for rejected product rows only.
    for (cve_id, repo_key), products in reject_products_by_pair.items():
        for product_norm in products:
            cur = conn.execute(
                """
                DELETE FROM version_cve_index
                WHERE rowid IN (
                    SELECT v.rowid
                    FROM version_cve_index v
                    JOIN nvd_cpe_ranges r ON v.range_id = r.range_id
                    WHERE v.cve_id = ?
                      AND v.repo_key = ?
                      AND lower(replace(replace(replace(coalesce(r.product,''), '-', '_'), '.', '_'), ' ', '_')) = ?
                )
                """,
                (cve_id, repo_key, product_norm),
            )
            stats["version_index_rows_deleted_for_reject_products"] += cur.rowcount if cur.rowcount != -1 else 0

    # Delete cve_github_refs for reject rows unless same CVE-repo is kept for another product line.
    for row in row_reject_rows:
        cve_id = get_first(row, "cve_id").upper()
        repo_key = norm_repo_key(get_first(row, "repo_key"))
        github_url = get_first(row, "github_url")
        if not cve_id or not repo_key or not github_url:
            continue
        if (cve_id, repo_key) in MANUAL_KEEP_CVE_REPO_REF:
            stats["reject_ref_kept_for_other_product_line"] += 1
            continue

        conn.execute(
            """
            INSERT INTO manual_fix_deleted_cve_github_refs
            SELECT datetime('now'), ?, r.*
            FROM cve_github_refs r
            WHERE r.cve_id = ? AND r.repo_key = ? AND r.github_url = ?
            """,
            ("manual_override_reject_csv_delete_ref", cve_id, repo_key, github_url),
        )
        cur = conn.execute(
            "DELETE FROM cve_github_refs WHERE cve_id = ? AND repo_key = ? AND github_url = ?",
            (cve_id, repo_key, github_url),
        )
        stats["cve_github_refs_deleted_for_reject"] += cur.rowcount if cur.rowcount != -1 else 0

    # Static manual correct product-line refs.
    for row in MANUAL_CORRECT_REFS:
        insert_ref_row(conn, row, source_prefix="correct_product_line")
        stats["static_correct_product_line_refs_inserted"] += 1

    # Product-line allow for static corrections.
    for row in MANUAL_CORRECT_REFS:
        cve_id = str(row["cve_id"]).upper()
        rk = norm_repo_key(row["repo_key"])
        prod = norm_product(row["product"])
        conn.execute(
            """
            INSERT OR REPLACE INTO manual_product_line_allow(cve_id, repo_key, allowed_product_norm, reason)
            VALUES (?, ?, ?, ?)
            """,
            (cve_id, rk, prod, row["reason"]),
        )

    # Summary marker
    conn.execute(
        "INSERT OR REPLACE INTO build_summary(key, value) VALUES (?, ?)",
        (
            "manual_override:csv_batch_patch",
            json.dumps({"fixed_at": now(), "stats": dict(stats)}, ensure_ascii=False, sort_keys=True),
        ),
    )
    return stats


# ------------------------------------------------------------
# Refresh ranges and partial reindex
# ------------------------------------------------------------

def affected_cves_from_db(conn: sqlite3.Connection) -> Set[str]:
    out: Set[str] = set()
    for table in ["manual_cve_repo_accept_overrides", "manual_cve_repo_reject_overrides", "manual_product_line_allow"]:
        if not table_exists(conn, table):
            continue
        for r in conn.execute(f"SELECT DISTINCT cve_id FROM {q(table)} WHERE cve_id IS NOT NULL AND cve_id <> ''"):
            out.add(str(r["cve_id"]).upper())
    for row in MANUAL_CORRECT_REFS:
        out.add(str(row["cve_id"]).upper())
    return out


def refresh_nvd_ranges_for_cves(conn: sqlite3.Connection, builder, nvd_input: Path, affected: Set[str]) -> Counter:
    stats = Counter()
    if not affected:
        return stats
    qmarks = ",".join("?" for _ in affected)
    conn.execute(f"DELETE FROM nvd_cpe_ranges WHERE cve_id IN ({qmarks})", sorted(affected))

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
    seen = set()
    for cve, raw in builder.iter_nvd_records(nvd_input):
        cve_id = builder.extract_cve_id(cve, raw)
        if not cve_id or cve_id.upper() not in affected:
            continue
        stats["nvd_target_records_seen"] += 1
        for row in builder.make_cpe_range_rows(cve_id, cve, raw):
            if not builder.cpe_range_has_version_info(row):
                stats["range_skip_no_version_info"] += 1
                continue
            key = (
                row.get("cve_id"), row.get("cpe_uri"), row.get("version_start_including"),
                row.get("version_start_excluding"), row.get("version_end_including"),
                row.get("version_end_excluding"), row.get("match_criteria_id"),
            )
            if key in seen:
                continue
            seen.add(key)
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


def partial_reindex(conn: sqlite3.Connection, builder, affected: Set[str]) -> Counter:
    stats = Counter()
    if not affected:
        return stats

    qmarks = ",".join("?" for _ in affected)
    conn.execute(f"DELETE FROM version_cve_index WHERE cve_id IN ({qmarks})", sorted(affected))
    stats["old_version_index_deleted_for_affected_cves"] = conn.total_changes

    allow_map: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    if table_exists(conn, "manual_product_line_allow"):
        for r in conn.execute("SELECT cve_id, repo_key, allowed_product_norm FROM manual_product_line_allow"):
            allow_map[(str(r["cve_id"]).upper(), norm_repo_key(r["repo_key"]))].add(norm_product(r["allowed_product_norm"]))

    reject_map: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    if table_exists(conn, "manual_cve_repo_reject_overrides"):
        for r in conn.execute("SELECT cve_id, repo_key, product FROM manual_cve_repo_reject_overrides"):
            if r["product"]:
                reject_map[(str(r["cve_id"]).upper(), norm_repo_key(r["repo_key"]))].add(norm_product(r["product"]))

    versions_by_repo: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in conn.execute("SELECT repo_key, version_raw, version_norm, source FROM github_versions"):
        versions_by_repo[norm_repo_key(r["repo_key"])].append(dict(r))

    refs_by_pair: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for r in conn.execute(f"SELECT cve_id, repo_key, github_url FROM cve_github_refs WHERE cve_id IN ({qmarks})", sorted(affected)):
        refs_by_pair[(str(r["cve_id"]).upper(), norm_repo_key(r["repo_key"]))].append(r["github_url"])

    ranges_by_cve: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in conn.execute(f"SELECT * FROM nvd_cpe_ranges WHERE cve_id IN ({qmarks})", sorted(affected)):
        ranges_by_cve[str(r["cve_id"]).upper()].append(dict(r))

    insert_sql = """
        INSERT OR IGNORE INTO version_cve_index
        (
            cve_id, repo_key, version_raw, version_norm, version_source,
            range_id, cpe_uri, match_reason, github_refs_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    for (cve_id, repo_key), urls in sorted(refs_by_pair.items()):
        versions = versions_by_repo.get(repo_key, [])
        if not versions:
            stats["skip_no_github_versions"] += 1
            continue

        allowed_products = allow_map.get((cve_id, repo_key), set())
        rejected_products = reject_map.get((cve_id, repo_key), set())
        refs_json = json.dumps(sorted(set(urls)), ensure_ascii=False)

        for rng in ranges_by_cve.get(cve_id, []):
            prod = norm_product(rng.get("product"))

            # If this pair has explicit allowed product list, only those product rows can index.
            if allowed_products and prod not in allowed_products:
                stats["skip_product_line_allow_guard"] += 1
                continue

            # Else skip explicit reject product rows.
            if prod in rejected_products:
                stats["skip_product_line_reject_guard"] += 1
                continue

            for ver in versions:
                ok, reason = builder.version_matches_range(ver["version_raw"], rng)
                if not ok:
                    stats[f"version_not_match:{reason}"] += 1
                    continue
                conn.execute(
                    insert_sql,
                    (
                        cve_id, repo_key, ver["version_raw"], ver["version_norm"], ver["source"],
                        rng["range_id"], rng["cpe_uri"], reason, refs_json,
                    ),
                )
                stats["version_index_insert_attempt"] += 1

    return stats


# ------------------------------------------------------------
# Exports
# ------------------------------------------------------------

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


def export_results(conn: sqlite3.Connection, export_dir: Path, affected: Set[str]) -> None:
    export_dir.mkdir(parents=True, exist_ok=True)
    if affected:
        qmarks = ",".join("?" for _ in affected)
        params = sorted(affected)
        dump_query(
            conn,
            f"SELECT * FROM cve_github_refs WHERE cve_id IN ({qmarks}) ORDER BY cve_id, repo_key, github_url",
            export_dir / "affected_cve_github_refs.csv",
            params,
        )
        dump_query(
            conn,
            f"SELECT * FROM version_cve_index WHERE cve_id IN ({qmarks}) ORDER BY cve_id, repo_key, version_raw",
            export_dir / "affected_version_cve_index.csv",
            params,
        )
        dump_query(
            conn,
            f"""
            SELECT v.cve_id, v.repo_key, r.vendor, r.product, COUNT(*) AS rows
            FROM version_cve_index v
            JOIN nvd_cpe_ranges r ON v.range_id = r.range_id
            WHERE v.cve_id IN ({qmarks})
            GROUP BY v.cve_id, v.repo_key, r.vendor, r.product
            ORDER BY v.cve_id, v.repo_key, r.product
            """,
            export_dir / "affected_product_line_index_summary.csv",
            params,
        )

    for table in [
        "manual_repo_accept_overrides",
        "manual_cve_repo_accept_overrides",
        "manual_cve_repo_reject_overrides",
        "manual_product_line_allow",
        "manual_keep_cve_repo_ref",
        "manual_fix_deleted_cve_github_refs",
        "manual_fix_inserted_cve_github_refs",
    ]:
        if table_exists(conn, table):
            dump_query(conn, f"SELECT * FROM {q(table)}", export_dir / f"{table}.csv")


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="version_cve_refiltered.db path")
    ap.add_argument("--csv-dir", required=True, help="manual_overrides directory")
    ap.add_argument("--builder-script", default="./scripts/02-04_refilteringNbuild_nvd2db.py")
    ap.add_argument("--github-cache", default="./workspace/github_cache")
    ap.add_argument("--nvd-input", default="", help="NVD filtered/merged JSON. 필요 시 affected CVE ranges refresh에 사용")
    ap.add_argument("--refresh-affected-ranges", action="store_true", help="--nvd-input 기준으로 affected CVE의 nvd_cpe_ranges 재삽입")
    ap.add_argument("--skip-cache-reload", action="store_true")
    ap.add_argument("--skip-reindex", action="store_true")
    ap.add_argument("--backup", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--export-dir", default="manual_overrides_exports")
    args = ap.parse_args()

    db = Path(args.db).resolve()
    csv_dir = Path(args.csv_dir).resolve()
    builder_script = Path(args.builder_script).resolve()
    github_cache = Path(args.github_cache).resolve()
    nvd_input = Path(args.nvd_input).resolve() if args.nvd_input else None
    export_dir = Path(args.export_dir).resolve()

    if not db.exists():
        raise FileNotFoundError(db)
    if not csv_dir.exists():
        raise FileNotFoundError(csv_dir)
    if not builder_script.exists():
        raise FileNotFoundError(builder_script)
    if not github_cache.exists():
        raise FileNotFoundError(github_cache)
    if args.refresh_affected_ranges and not nvd_input:
        raise RuntimeError("--refresh-affected-ranges requires --nvd-input")
    if nvd_input and not nvd_input.exists():
        raise FileNotFoundError(nvd_input)

    if args.backup:
        backup = db.with_suffix(db.suffix + f".bak_manual_override_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        shutil.copy2(db, backup)
        print(f"[BACKUP] {backup}")

    print("[LOAD] override CSVs")
    repo_accept_rows, row_accept_rows, row_reject_rows, load_stats = load_override_rows(csv_dir)
    print(json.dumps(dict(load_stats), indent=2, ensure_ascii=False))

    builder = load_builder(builder_script)
    conn = connect(db)

    try:
        print("[STEP 1] apply manual overrides")
        conn.execute("BEGIN")
        patch_stats = apply_overrides(conn, repo_accept_rows, row_accept_rows, row_reject_rows)
        conn.commit()
        print(json.dumps(dict(patch_stats), indent=2, ensure_ascii=False))

        affected = affected_cves_from_db(conn)
        print(f"[INFO] affected_cves={len(affected)}")
        if affected:
            print("[INFO] affected sample:", ", ".join(sorted(affected)[:20]))

        range_stats = Counter()
        if args.refresh_affected_ranges:
            print("[STEP 2] refresh affected nvd_cpe_ranges from NVD")
            conn.execute("BEGIN")
            range_stats = refresh_nvd_ranges_for_cves(conn, builder, nvd_input, affected)
            conn.commit()
            print(json.dumps(dict(range_stats), indent=2, ensure_ascii=False))
        else:
            print("[STEP 2] skip nvd_cpe_ranges refresh")

        cache_stats = Counter()
        if not args.skip_cache_reload:
            print("[STEP 3] reload GitHub cache into DB")
            cache_stats = builder.load_github_cache(conn, github_cache)
            print(json.dumps(dict(cache_stats), indent=2, ensure_ascii=False))
        else:
            print("[STEP 3] skip GitHub cache reload")

        reindex_stats = Counter()
        if not args.skip_reindex:
            print("[STEP 4] partial reindex affected CVEs")
            conn.execute("BEGIN")
            reindex_stats = partial_reindex(conn, builder, affected)
            conn.commit()
            print(json.dumps(dict(reindex_stats), indent=2, ensure_ascii=False))
        else:
            print("[STEP 4] skip partial reindex")

        summary = {
            "applied_at": now(),
            "db": str(db),
            "csv_dir": str(csv_dir),
            "builder_script": str(builder_script),
            "github_cache": str(github_cache),
            "nvd_input": str(nvd_input) if nvd_input else None,
            "dry_run": args.dry_run,
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

        print("[STEP 5] export verification CSVs")
        export_results(conn, export_dir, affected)
        with (export_dir / "manual_override_apply_summary.json").open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, sort_keys=True)
        print(f"[EXPORT] {export_dir}")

        if args.dry_run:
            print("[DRY-RUN] rolling back by restoring from transaction is not possible after commits; use --backup and restore backup if needed.")
            print("[DRY-RUN NOTE] This script commits per step for large DB safety. For true dry-run, run on a copied DB.")

    finally:
        conn.close()

    print("[DONE]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
