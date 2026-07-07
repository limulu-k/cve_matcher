#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
04_build_final_db_binding_v3.py

Fresh single-pass final builder for the CVE/GitHub/version SQLite DB.

Design goal
-----------
Keep the existing high-level flow, but fix the semantic bug in the version index:

    CVE -> repo evidence                 != repo -> CPE product/range binding

The old failure mode was effectively:

    github_versions(repo) JOIN cve_github_refs(repo,cve) JOIN nvd_cpe_ranges(cve)

That cross-products every repo attached to a multi-product CVE with every CPE range
inside the CVE. This script builds an explicit in-memory/exported binding:

    (cve_id, repo_key, range_id)

and creates version_cve_index only from those accepted bindings.

High-level flow preserved
-------------------------
STEP 1  Input / allowlist / codex/manual CSV load
STEP 2  NVD parse: cves, GitHub refs, CPE ranges
STEP 3  Base rule classification: accept / reject / review candidate pairs
STEP 4  Manual override application
STEP 5  Codex accept/reject application AFTER the existing-flow stages
STEP 6  GitHub cache load for selected allowlisted repos
STEP 7  Range-bound version_cve_index build
STEP 8  Final DB write with only core 8 tables
STEP 9  Audit CSV/JSON exports

Final DB tables
---------------
build_summary, cve_github_refs, cves, github_commits, github_versions,
nvd_cpe_ranges, repositories, version_cve_index

Important behavior fixes
------------------------
1. version_cve_index is built only from accepted CVE-repo-CPE-range bindings.
2. GitHub redirect accept rows are stored/indexed under canonical_repo_key when possible.
3. 404 evidence rows are preserved in cve_github_refs with accepted_range metadata, but
   they do not create fake version index rows when no GitHub versions exist.
4. All final repo-bearing tables are guarded by git/ allowlist; allowlist outsiders are
   skipped rather than inserted.
5. reject_list is audit/guard data only; it is not inserted into the final DB.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
import shutil
import sqlite3
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

GITHUB_PATTERNS = [
    # More specific host forms must come before the generic github.com pattern.
    # Otherwise https://api.github.com/repos/OWNER/REPO can be mis-parsed as repos@OWNER.
    re.compile(r"(?:https?://)?api\.github\.com/repos/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"(?:https?://)?raw\.githubusercontent\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"(?:https?://)?codeload\.github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"git\+https?://github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"ssh://git@github\.com[:/]([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    re.compile(r"git@github\.com[:/]([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
    # Generic github.com matcher. The negative lookbehind prevents matching
    # the github.com suffix inside api.github.com or codeload.github.com.
    re.compile(r"(?<![A-Za-z0-9_.-])(?:https?://)?(?:www\.)?github\.com/([^/\s\"'<>]+)/([^/\s\"'<>#?]+)", re.I),
]
COMMIT_RE = re.compile(r"/commit/([0-9a-f]{7,40})(?:[^0-9a-f]|$)", re.I)
TAG_RE = re.compile(r"/(?:releases/tag|tree|commits?)/([^/?#\s\"'<>]+)", re.I)

WILDCARD_VERSIONS = {"", "*", "-", "n/a", "na", "any", "all", "unspecified", "null", "none"}

GENERIC_TOKENS = {
    "project", "software", "system", "service", "tool", "tools", "common", "commons",
    "main", "base", "utils", "utility", "app", "application", "server", "client",
}

QUALIFIER_TOKENS = {
    "js", "javascript", "node", "nodejs", "php", "python", "py", "ruby", "rb",
    "java", "go", "golang", "cpp", "c", "csharp", "net", "core", "src", "lib",
    "library", "framework", "plugin", "module", "sdk", "api", "cli", "server", "client",
    "web", "ui", "cms", "app", "application", "package", "gem", "npm", "wordpress",
}

SOFT_NON_PRODUCT_TOKENS = {
    "sample", "samples", "demo", "example", "examples", "tutorial", "template", "starter",
    "docs", "documentation", "website", "awesome", "test", "tests", "benchmark",
}

HARD_NON_PRODUCT_TOKENS = {
    "poc", "pocs", "exploit", "exploits", "rce", "cve", "cves", "vuln", "vulnerability",
    "advisory", "advisories", "writeup", "writeups", "metasploit", "nuclei", "oss-fuzz",
    "ossfuzz", "cvelist", "security-advisories", "advisory-db", "nuclei-templates",
}

OS_DISTRO_PRODUCTS = {
    "debian_linux", "ubuntu_linux", "fedora", "enterprise_linux", "enterprise_linux_server",
    "enterprise_linux_desktop", "enterprise_linux_workstation", "enterprise_linux_eus",
    "opensuse", "leap", "suse_linux_enterprise_server", "suse_linux_enterprise_desktop",
    "freebsd", "netbsd", "openbsd", "mac_os_x", "macos", "ios", "ipados", "android",
}

# If qualifier removal leaves only one of these protocol/platform words,
# it is not enough to bind a repo to a product line. Example:
# net-ssh != bitvise:ssh_client even though both contain "ssh".
WEAK_QUALIFIER_CORE_TOKENS = {
    "ssh", "ssl", "tls", "http", "https", "ftp", "smtp", "imap", "dns", "xml",
    "json", "api", "sdk", "client", "server", "core", "lib", "web", "ui", "net",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GitHubRef:
    cve_id: str
    repo_key: str
    github_url: str
    source: str
    ref_kind: str = "repo_or_file"
    commit_sha: str = ""
    tag_name: str = ""
    reference_json: str = ""


@dataclass
class CVERow:
    cve_id: str
    published: str = ""
    last_modified: str = ""
    vuln_status: str = ""
    description: str = ""


@dataclass
class CPERange:
    range_id: int
    cve_id: str
    cpe_uri: str
    part: str
    vendor: str
    product: str
    cpe_version: str
    version_start_including: str
    version_start_excluding: str
    version_end_including: str
    version_end_excluding: str
    vulnerable: int
    match_criteria_id: str
    raw_json: str
    range_key: str


@dataclass(frozen=True)
class BindingKey:
    cve_id: str
    repo_key: str
    range_id: int


@dataclass
class Binding:
    cve_id: str
    repo_key: str
    range_id: int
    range_key: str
    vendor: str
    product: str
    cpe_uri: str
    github_url: str
    decision_source: str
    decision_rule: str
    decision_reason: str
    evidence_only: bool = False
    original_repo_key: str = ""
    original_github_url: str = ""


@dataclass
class CandidateAudit:
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
    fitness_score: float
    hard_tokens: str
    soft_tokens: str
    decision: str
    decision_rule: str
    reject_reason: str


# ---------------------------------------------------------------------------
# Generic utilities
# ---------------------------------------------------------------------------

def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return json.dumps(str(obj), ensure_ascii=False)


def as_text(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def lower_text(v: Any) -> str:
    return as_text(v).lower()


def norm_piece(s: Any) -> str:
    x = lower_text(s)
    x = unquote(x)
    if x.endswith(".git"):
        x = x[:-4]
    x = x.strip("/@ ")
    return x


def repo_key(owner: Any, repo: Any) -> str:
    return f"{norm_piece(owner)}@{norm_piece(repo)}"


def norm_repo_key(value: Any) -> str:
    x = lower_text(value)
    x = unquote(x)
    x = x.replace("https://github.com/", "")
    x = x.replace("http://github.com/", "")
    x = x.replace("git@github.com:", "")
    x = x.replace("git@github.com/", "")
    x = x.strip().strip("/")
    if "@" in x:
        a, b = x.split("@", 1)
        return repo_key(a, b)
    if "/" in x:
        a, b = x.split("/", 1)
        return repo_key(a, b.split("/", 1)[0])
    return x


def split_repo_key(rk: str) -> Tuple[str, str]:
    rk = norm_repo_key(rk)
    if "@" not in rk:
        return rk, ""
    return tuple(rk.split("@", 1))  # type: ignore[return-value]


def parse_github_url(url: Any) -> Optional[Tuple[str, str, str]]:
    s = as_text(url)
    if not s:
        return None
    for pat in GITHUB_PATTERNS:
        m = pat.search(s)
        if not m:
            continue
        owner = norm_piece(m.group(1))
        repo = norm_piece(m.group(2))
        if not owner or not repo:
            continue
        if owner in {"advisories", "topics", "marketplace", "collections", "explore"}:
            return None
        if repo.startswith("ghsa-"):
            return None
        return owner, repo, f"{owner}@{repo}"
    return None


def find_github_urls(text: Any) -> List[str]:
    s = as_text(text)
    if not s:
        return []
    urls: List[str] = []
    # Broad capture first, then validate through parse_github_url.
    patterns = [
        # Specific forms first. Keep generic github.com last to avoid
        # extracting github.com/repos/OWNER from api.github.com/repos/OWNER/REPO.
        r"(?:https?://)?api\.github\.com/repos/[^\s\"'<>]+",
        r"(?:https?://)?raw\.githubusercontent\.com/[^\s\"'<>]+",
        r"(?:https?://)?codeload\.github\.com/[^\s\"'<>]+",
        r"git\+https?://github\.com/[^\s\"'<>]+",
        r"ssh://git@github\.com[:/][^\s\"'<>]+",
        r"git@github\.com[:/][^\s\"'<>]+",
        r"(?<![A-Za-z0-9_.-])(?:https?://)?(?:www\.)?github\.com/[^\s\"'<>]+",
    ]
    for p in patterns:
        for m in re.finditer(p, s, flags=re.I):
            u = m.group(0).rstrip(".,);]")
            if parse_github_url(u):
                urls.append(u)
    return sorted(set(urls))


def infer_ref_kind(url: str) -> Tuple[str, str, str]:
    commit_sha = ""
    tag_name = ""
    kind = "repo_or_file"
    m = COMMIT_RE.search(url)
    if m:
        commit_sha = m.group(1).lower()
        kind = "commit"
    else:
        mt = TAG_RE.search(url)
        if mt:
            tag_name = unquote(mt.group(1))
            kind = "tag_or_tree"
        elif "/pull/" in url:
            kind = "pull"
        elif "/issues/" in url:
            kind = "issue"
        elif "/blob/" in url or "/raw/" in url:
            kind = "file"
        elif "/security/advisories/" in url:
            kind = "advisory"
    return kind, commit_sha, tag_name


def normalize_name(s: Any) -> str:
    x = unicodedata.normalize("NFKC", lower_text(s))
    x = x.replace("\\/", "/")
    x = re.sub(r"[^a-z0-9]+", "_", x)
    x = re.sub(r"_+", "_", x).strip("_")
    return x


def compact(s: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize_name(s))


def tokens(s: Any) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", normalize_name(s)) if t]


def token_string_without(s: Any, remove: Set[str]) -> str:
    return "_".join(t for t in tokens(s) if t not in remove)


def seq_ratio(a: Any, b: Any) -> float:
    aa = compact(a)
    bb = compact(b)
    if not aa or not bb:
        return 0.0
    if aa == bb:
        return 1.0
    if aa in bb or bb in aa:
        return min(len(aa), len(bb)) / max(len(aa), len(bb))
    return SequenceMatcher(None, aa, bb).ratio()


def relation_score(repo_or_owner: str, vendor_or_product: str) -> Tuple[float, str]:
    a = normalize_name(repo_or_owner)
    b = normalize_name(vendor_or_product)
    ca = compact(a)
    cb = compact(b)
    if not ca or not cb:
        return 0.0, "empty"
    if ca == cb:
        return 1.0, "compact_equal"

    # Remove generic/qualifier tokens for product-name comparisons.
    a_core = token_string_without(a, GENERIC_TOKENS | QUALIFIER_TOKENS)
    b_core = token_string_without(b, GENERIC_TOKENS | QUALIFIER_TOKENS)
    if a_core and b_core and compact(a_core) == compact(b_core):
        core = compact(a_core)
        # Do not treat a single weak protocol/platform token as product identity.
        if core in WEAK_QUALIFIER_CORE_TOKENS or len(core) < 4:
            return 0.68, "qualifier_removed_weak_core"
        return 0.92, "qualifier_removed_equal"

    if ca in cb or cb in ca:
        small = min(len(ca), len(cb))
        large = max(len(ca), len(cb))
        score = 0.76 + 0.20 * (small / large)
        return min(score, 0.96), "compact_subset"

    # Token overlap.
    at = set(tokens(a)) - GENERIC_TOKENS
    bt = set(tokens(b)) - GENERIC_TOKENS
    if at and bt:
        j = len(at & bt) / len(at | bt)
    else:
        j = 0.0
    sr = seq_ratio(a, b)
    score = max(sr, j)
    return score, "fuzzy"


def detect_nonproduct_tokens(owner: str, repo: str) -> Tuple[Set[str], Set[str]]:
    ts = set(tokens(owner)) | set(tokens(repo))
    hard = {t for t in ts if t in HARD_NON_PRODUCT_TOKENS}
    soft = {t for t in ts if t in SOFT_NON_PRODUCT_TOKENS}
    # Composite phrases
    joined = "-".join(tokens(repo))
    for phrase in ["security-advisories", "advisory-db", "nuclei-templates", "cve-poc"]:
        if phrase in joined:
            hard.add(phrase)
    return hard, soft


def normalize_version_string(s: Any) -> str:
    raw = as_text(s)
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
    out: List[Any] = []
    for p in re.findall(r"\d+|[a-zA-Z]+", ns):
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


def version_matches_range(version: str, rng: CPERange) -> Tuple[bool, str]:
    candidate = normalize_version_string(version)
    if not candidate:
        return False, "skip_empty_version"

    exact = rng.cpe_version
    start_inc = rng.version_start_including
    start_exc = rng.version_start_excluding
    end_inc = rng.version_end_including
    end_exc = rng.version_end_excluding
    has_range = any(x not in WILDCARD_VERSIONS for x in [start_inc, start_exc, end_inc, end_exc])

    if exact not in WILDCARD_VERSIONS and not has_range:
        c = cmp_version(candidate, exact)
        if c == 0 or normalize_version_string(candidate) == normalize_version_string(exact):
            return True, "exact_cpe_version_match"
        return False, "not_exact_cpe_version"

    if not has_range:
        return False, "skip_no_usable_version_range"

    if start_inc not in WILDCARD_VERSIONS:
        c = cmp_version(candidate, start_inc)
        if c is None:
            return False, "skip_uncomparable_start_including"
        if c < 0:
            return False, "below_start_including"

    if start_exc not in WILDCARD_VERSIONS:
        c = cmp_version(candidate, start_exc)
        if c is None:
            return False, "skip_uncomparable_start_excluding"
        if c <= 0:
            return False, "below_or_equal_start_excluding"

    if end_inc not in WILDCARD_VERSIONS:
        c = cmp_version(candidate, end_inc)
        if c is None:
            return False, "skip_uncomparable_end_including"
        if c > 0:
            return False, "above_end_including"

    if end_exc not in WILDCARD_VERSIONS:
        c = cmp_version(candidate, end_exc)
        if c is None:
            return False, "skip_uncomparable_end_excluding"
        if c >= 0:
            return False, "above_or_equal_end_excluding"

    return True, "range_match"


# ---------------------------------------------------------------------------
# CPE parsing and NVD parsing
# ---------------------------------------------------------------------------

def split_escaped_colons(s: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    esc = False
    for ch in s:
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
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def cpe_unescape(s: Any) -> str:
    x = as_text(s)
    x = x.replace("\\/", "/").replace("\\:", ":").replace("\\_", "_")
    return x


def parse_cpe23(cpe_uri: str) -> Tuple[str, str, str, str]:
    # returns part, vendor, product, version
    if not cpe_uri.startswith("cpe:2.3:"):
        return "", "", "", ""
    parts = split_escaped_colons(cpe_uri)
    # cpe, 2.3, part, vendor, product, version, ...
    if len(parts) < 6:
        return "", "", "", ""
    part = cpe_unescape(parts[2]).lower()
    vendor = normalize_name(cpe_unescape(parts[3]))
    product = normalize_name(cpe_unescape(parts[4]))
    version = cpe_unescape(parts[5]).lower()
    return part, vendor, product, version


def make_range_key(cpe_uri: str, vsi: str, vse: str, vei: str, vee: str) -> str:
    return "|".join([as_text(cpe_uri), as_text(vsi), as_text(vse), as_text(vei), as_text(vee)])


def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def load_json_or_jsonl(path: Path) -> Iterator[Any]:
    """Load NVD input as either normal JSON or JSONL/NDJSON.

    ./data/filtered.json in this project is often JSONL even when the
    extension is .json. json.load() then raises JSONDecodeError: Extra data.
    This function first tries whole-file JSON and falls back to line-by-line
    JSON parsing. It also tolerates array-like JSONL files whose lines end
    with commas.
    """
    with open_text(path) as f:
        prefix = f.read(4096)
        f.seek(0)
        stripped = prefix.lstrip()

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                yield json.load(f)
                return
            except json.JSONDecodeError:
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
            except json.JSONDecodeError as e:
                print(f"[WARN] skip malformed JSON line {path}:{line_no}: {e}", file=sys.stderr)
                continue


def iter_nvd_records(obj: Any) -> Iterator[Dict[str, Any]]:
    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                yield x
        return
    if not isinstance(obj, dict):
        return
    for key in ["vulnerabilities", "CVE_Items", "items", "records"]:
        xs = obj.get(key)
        if isinstance(xs, list):
            for x in xs:
                if isinstance(x, dict):
                    yield x
            return
    # Single record fallback.
    if "cve" in obj or "cve_id" in obj:
        yield obj


def get_cve_obj(record: Dict[str, Any]) -> Dict[str, Any]:
    cve = record.get("cve")
    return cve if isinstance(cve, dict) else record


def extract_cve_id(record: Dict[str, Any]) -> str:
    cve = get_cve_obj(record)
    for path in [
        ("id",),
        ("cve_id",),
        ("CVE_data_meta", "ID"),
    ]:
        cur: Any = cve
        for p in path:
            cur = cur.get(p) if isinstance(cur, dict) else None
        if isinstance(cur, str) and CVE_RE.fullmatch(cur.strip()):
            return cur.strip().upper()
    # Search the whole record as last resort.
    m = CVE_RE.search(safe_json(record))
    return m.group(0).upper() if m else ""


def extract_description(cve: Dict[str, Any]) -> str:
    descs = cve.get("descriptions")
    if isinstance(descs, list):
        for d in descs:
            if isinstance(d, dict) and lower_text(d.get("lang")) == "en":
                return as_text(d.get("value"))
        for d in descs:
            if isinstance(d, dict) and d.get("value"):
                return as_text(d.get("value"))
    legacy = cve.get("description")
    if isinstance(legacy, dict):
        xs = legacy.get("description_data")
        if isinstance(xs, list):
            for d in xs:
                if isinstance(d, dict) and lower_text(d.get("lang")) == "en":
                    return as_text(d.get("value"))
            for d in xs:
                if isinstance(d, dict) and d.get("value"):
                    return as_text(d.get("value"))
    return ""


def extract_references(cve: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = cve.get("references")
    out: List[Dict[str, Any]] = []
    if isinstance(refs, dict):
        xs = refs.get("referenceData") or refs.get("references")
        if isinstance(xs, list):
            refs = xs
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, dict):
                url = r.get("url") or r.get("href")
                if url:
                    out.append(r)
            elif isinstance(r, str):
                out.append({"url": r})
    return out


def iter_cpe_matches_from_node(node: Any) -> Iterator[Dict[str, Any]]:
    if not isinstance(node, dict):
        return
    xs = node.get("cpeMatch") or node.get("cpe_match")
    if isinstance(xs, list):
        for x in xs:
            if isinstance(x, dict):
                yield x
    # NVD 2.0 may wrap nodes as configurations[{"nodes": [...]}].
    nested_nodes = node.get("nodes")
    if isinstance(nested_nodes, list):
        for ch in nested_nodes:
            yield from iter_cpe_matches_from_node(ch)

    children = node.get("children")
    if isinstance(children, list):
        for ch in children:
            yield from iter_cpe_matches_from_node(ch)


def extract_cpe_matches(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    cve = get_cve_obj(record)
    configs = cve.get("configurations") or record.get("configurations")
    out: List[Dict[str, Any]] = []
    if isinstance(configs, dict):
        nodes = configs.get("nodes")
    else:
        nodes = configs
    if isinstance(nodes, list):
        for n in nodes:
            out.extend(iter_cpe_matches_from_node(n))
    return out


@dataclass
class ParsedNVD:
    cves: Dict[str, CVERow] = field(default_factory=dict)
    refs_by_cve: Dict[str, List[GitHubRef]] = field(default_factory=lambda: defaultdict(list))
    ranges_by_cve: Dict[str, List[CPERange]] = field(default_factory=lambda: defaultdict(list))
    range_by_key: Dict[Tuple[str, str], CPERange] = field(default_factory=dict)
    stats: Counter = field(default_factory=Counter)


def parse_nvd(path: Path) -> ParsedNVD:
    parsed = ParsedNVD()
    seen_ranges: Set[Tuple[str, str]] = set()
    next_range_id = 1

    for obj in load_json_or_jsonl(path):
        for rec in iter_nvd_records(obj):
            cve_obj = get_cve_obj(rec)
            cve_id = extract_cve_id(rec)
            if not cve_id:
                parsed.stats["nvd:skip_no_cve_id"] += 1
                continue

            cve_row = CVERow(
                cve_id=cve_id,
                published=as_text(cve_obj.get("published") or rec.get("published")),
                last_modified=as_text(
                    cve_obj.get("lastModified") or cve_obj.get("last_modified") or rec.get("lastModified") or rec.get("last_modified")
                ),
                vuln_status=as_text(cve_obj.get("vulnStatus") or cve_obj.get("vuln_status") or rec.get("vulnStatus")),
                description=extract_description(cve_obj),
            )
            parsed.cves[cve_id] = cve_row
            parsed.stats["nvd:records"] += 1

            # GitHub refs from references.
            for ref in extract_references(cve_obj):
                url = as_text(ref.get("url") or ref.get("href"))
                p = parse_github_url(url)
                if not p:
                    continue
                owner, repo, rk = p
                kind, sha, tag = infer_ref_kind(url)
                parsed.refs_by_cve[cve_id].append(
                    GitHubRef(
                        cve_id=cve_id,
                        repo_key=rk,
                        github_url=url,
                        source="ref",
                        ref_kind=kind,
                        commit_sha=sha,
                        tag_name=tag,
                        reference_json=safe_json(ref),
                    )
                )
                parsed.stats["nvd:github_ref_url"] += 1

            # GitHub refs from description as fallback evidence.
            for url in find_github_urls(cve_row.description):
                p = parse_github_url(url)
                if not p:
                    continue
                owner, repo, rk = p
                kind, sha, tag = infer_ref_kind(url)
                parsed.refs_by_cve[cve_id].append(
                    GitHubRef(
                        cve_id=cve_id,
                        repo_key=rk,
                        github_url=url,
                        source="description",
                        ref_kind=kind,
                        commit_sha=sha,
                        tag_name=tag,
                        reference_json=safe_json({"source": "description"}),
                    )
                )
                parsed.stats["nvd:github_description_url"] += 1

            # Ranges.
            for m in extract_cpe_matches(rec):
                vulnerable = m.get("vulnerable")
                if vulnerable is False:
                    parsed.stats["nvd:cpe_skip_not_vulnerable"] += 1
                    continue
                cpe_uri = as_text(m.get("criteria") or m.get("cpe23Uri") or m.get("cpe_uri"))
                if not cpe_uri:
                    continue
                part, vendor, product, cpe_version = parse_cpe23(cpe_uri)
                if not vendor or not product:
                    parsed.stats["nvd:cpe_skip_parse_fail"] += 1
                    continue
                vsi = as_text(m.get("versionStartIncluding") or m.get("version_start_including"))
                vse = as_text(m.get("versionStartExcluding") or m.get("version_start_excluding"))
                vei = as_text(m.get("versionEndIncluding") or m.get("version_end_including"))
                vee = as_text(m.get("versionEndExcluding") or m.get("version_end_excluding"))
                range_key = make_range_key(cpe_uri, vsi, vse, vei, vee)
                key = (cve_id, range_key)
                if key in seen_ranges:
                    continue
                seen_ranges.add(key)
                rng = CPERange(
                    range_id=next_range_id,
                    cve_id=cve_id,
                    cpe_uri=cpe_uri,
                    part=part,
                    vendor=vendor,
                    product=product,
                    cpe_version=cpe_version,
                    version_start_including=vsi,
                    version_start_excluding=vse,
                    version_end_including=vei,
                    version_end_excluding=vee,
                    vulnerable=1 if vulnerable is not False else 0,
                    match_criteria_id=as_text(m.get("matchCriteriaId") or m.get("match_criteria_id")),
                    raw_json=safe_json(m),
                    range_key=range_key,
                )
                next_range_id += 1
                parsed.ranges_by_cve[cve_id].append(rng)
                parsed.range_by_key[key] = rng
                parsed.stats["nvd:cpe_ranges"] += 1

    # Deduplicate GitHub refs per CVE after all JSON/JSONL records are processed.
    for cve_id, refs in list(parsed.refs_by_cve.items()):
        uniq = {(r.cve_id, r.repo_key, r.github_url): r for r in refs}
        parsed.refs_by_cve[cve_id] = list(uniq.values())

    return parsed


# ---------------------------------------------------------------------------
# Input allowlist / CSV loading
# ---------------------------------------------------------------------------

def load_git_allowlist(git_dir: Path) -> Dict[str, str]:
    allow: Dict[str, str] = {}
    if not git_dir.exists():
        return allow
    for p in sorted(git_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.name.startswith("._"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # Accept owner@repo or owner/repo or GitHub URL.
            rk = ""
            if parse_github_url(s):
                rk = parse_github_url(s)[2]  # type: ignore[index]
            elif "@" in s or "/" in s:
                rk = norm_repo_key(s.split()[0].strip(","))
            if rk and "@" in rk:
                allow[rk] = str(p)
    return allow


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return [dict(r) for r in csv.DictReader(f)]


def write_csv_rows(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Optional[List[str]] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: List[str] = []
        seen: Set[str] = set()
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    keys.append(k)
                    seen.add(k)
        fieldnames = keys
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def find_first_existing(base: Path, names: Sequence[str]) -> Optional[Path]:
    for n in names:
        p = base / n
        if p.exists():
            return p
    return None


# ---------------------------------------------------------------------------
# Candidate classification and bindings
# ---------------------------------------------------------------------------

def classify_pair(ref: GitHubRef, rng: CPERange, repo_nonproduct_allow: Set[str]) -> CandidateAudit:
    owner, repo = split_repo_key(ref.repo_key)
    owner_score, owner_rule = relation_score(owner, rng.vendor)
    repo_score, repo_rule = relation_score(repo, rng.product)
    fitness = 0.35 * owner_score + 0.65 * repo_score
    hard, soft = detect_nonproduct_tokens(owner, repo)

    # Product-name token exceptions: hard/soft words may be real product names.
    product_compact = compact(rng.product)
    repo_compact = compact(repo)
    hard_effective = set(hard)
    soft_effective = set(soft)
    if ref.repo_key in repo_nonproduct_allow:
        hard_effective.clear()
        soft_effective.clear()
    elif product_compact == repo_compact or product_compact in repo_compact or repo_compact in product_compact:
        # Do not reject solely because the product itself contains test/template/nuclei/etc.
        soft_effective.clear()
        if repo_score >= 0.90:
            hard_effective.clear()

    decision = "reject"
    rule = "below_threshold"
    reason = "below_threshold"

    if hard_effective:
        decision = "reject"
        rule = "hard_non_product_token"
        reason = "hard_non_product_token"
    elif rng.product in OS_DISTRO_PRODUCTS and repo_score < 0.95:
        decision = "reject"
        rule = "os_distro_product_boundary"
        reason = "os/distro CPE product must not be bound to upstream repo unless exact product match"
    elif repo_score >= 0.90 and (owner_score >= 0.08 or repo_rule in {"compact_equal", "qualifier_removed_equal"}):
        decision = "accept"
        rule = f"strong_product_relation:{repo_rule}"
        reason = "accepted by product/repo relation"
    elif fitness >= 0.88:
        decision = "accept"
        rule = "fitness_accept"
        reason = "accepted by combined owner/repo fitness"
    elif soft_effective and fitness < 0.85:
        decision = "review"
        rule = "soft_nonproduct_review"
        reason = "soft non-product token requires manual/codex review"
    elif fitness >= 0.68 or repo_score >= 0.76:
        decision = "review"
        rule = "borderline_review"
        reason = "borderline product/repo relation"
    else:
        decision = "reject"
        rule = "below_threshold"
        reason = "insufficient evidence that repo is canonical product repo for this CPE range"

    return CandidateAudit(
        cve_id=ref.cve_id,
        github_url=ref.github_url,
        source=ref.source,
        repo_key=ref.repo_key,
        owner=owner,
        repo=repo,
        vendor=rng.vendor,
        product=rng.product,
        cpe_uri=rng.cpe_uri,
        range_key=rng.range_key,
        owner_score=round(owner_score, 12),
        repo_score=round(repo_score, 12),
        fitness_score=round(fitness, 12),
        hard_tokens=";".join(sorted(hard)),
        soft_tokens=";".join(sorted(soft)),
        decision=decision,
        decision_rule=rule,
        reject_reason=reason,
    )


def add_binding(
    bindings: Dict[BindingKey, Binding],
    stats: Counter,
    cve_id: str,
    repo_key_value: str,
    rng: CPERange,
    github_url: str,
    decision_source: str,
    decision_rule: str,
    decision_reason: str,
    evidence_only: bool = False,
    original_repo_key: str = "",
    original_github_url: str = "",
) -> bool:
    rk = norm_repo_key(repo_key_value)
    key = BindingKey(cve_id.upper(), rk, rng.range_id)
    if key in bindings:
        stats[f"binding_duplicate:{decision_source}"] += 1
        return False
    bindings[key] = Binding(
        cve_id=cve_id.upper(),
        repo_key=rk,
        range_id=rng.range_id,
        range_key=rng.range_key,
        vendor=rng.vendor,
        product=rng.product,
        cpe_uri=rng.cpe_uri,
        github_url=github_url,
        decision_source=decision_source,
        decision_rule=decision_rule,
        decision_reason=decision_reason,
        evidence_only=evidence_only,
        original_repo_key=original_repo_key or rk,
        original_github_url=original_github_url or github_url,
    )
    stats[f"binding_added:{decision_source}"] += 1
    return True


def remove_binding_for_row(
    bindings: Dict[BindingKey, Binding],
    parsed: ParsedNVD,
    row: Dict[str, str],
    effective_repo: str,
    stats: Counter,
) -> int:
    cve_id = lower_text(row.get("cve_id")).upper()
    if not cve_id:
        return 0
    ranges = resolve_ranges_for_decision_row(parsed, row)
    removed = 0
    for rng in ranges:
        key = BindingKey(cve_id, effective_repo, rng.range_id)
        if key in bindings:
            del bindings[key]
            removed += 1
    if removed:
        stats["binding_removed_by_reject"] += removed
    return removed


# ---------------------------------------------------------------------------
# Decision row resolution
# ---------------------------------------------------------------------------

def effective_repo_from_decision_row(row: Dict[str, str], allowlist: Dict[str, str]) -> Tuple[str, str, str]:
    """Return (repo_key, chosen_url, reason). Enforces canonical redirect preference.

    The returned repo may still be outside allowlist; caller must enforce allowlist.
    """
    original = norm_repo_key(row.get("repo_key"))
    canonical = norm_repo_key(row.get("canonical_repo_key")) if row.get("canonical_repo_key") else ""
    suggested_url = as_text(row.get("normalized_or_suggested_github_url") or row.get("url_final_url"))
    suggested_parsed = parse_github_url(suggested_url)
    suggested_repo = suggested_parsed[2] if suggested_parsed else ""

    source_dataset = lower_text(row.get("source_dataset"))
    is_redirect = lower_text(row.get("url_is_redirect")) in {"1", "true", "yes", "y"} or "redirect" in source_dataset

    if canonical and canonical in allowlist:
        return canonical, suggested_url or as_text(row.get("github_url")), "canonical_repo_key_allowlisted"
    if suggested_repo and suggested_repo in allowlist and (is_redirect or original not in allowlist):
        return suggested_repo, suggested_url, "suggested_url_repo_allowlisted"
    if original:
        return original, as_text(row.get("github_url") or suggested_url), "original_repo_key"
    if suggested_repo:
        return suggested_repo, suggested_url, "suggested_url_repo"
    url = as_text(row.get("github_url"))
    p = parse_github_url(url)
    if p:
        return p[2], url, "parsed_github_url"
    return "", url, "no_repo"


def resolve_ranges_for_decision_row(parsed: ParsedNVD, row: Dict[str, str]) -> List[CPERange]:
    cve_id = lower_text(row.get("cve_id")).upper()
    if not cve_id:
        return []
    ranges = parsed.ranges_by_cve.get(cve_id, [])
    if not ranges:
        return []

    range_key = as_text(row.get("range_key"))
    cpe_uri = as_text(row.get("cpe_uri"))
    vendor = normalize_name(row.get("vendor"))
    product = normalize_name(row.get("product"))

    if range_key:
        rng = parsed.range_by_key.get((cve_id, range_key))
        if rng:
            return [rng]
        # tolerate cpe_uri-only range_key shapes
        hits = [r for r in ranges if r.range_key == range_key or r.cpe_uri == range_key]
        if hits:
            return hits

    if cpe_uri:
        hits = [r for r in ranges if r.cpe_uri == cpe_uri]
        if vendor:
            hits = [r for r in hits if r.vendor == vendor]
        if product:
            hits = [r for r in hits if r.product == product]
        if hits:
            return hits

    if vendor and product:
        hits = [r for r in ranges if r.vendor == vendor and r.product == product]
        if hits:
            return hits

    if product:
        hits = [r for r in ranges if r.product == product]
        if hits:
            return hits

    return []


def decision_exact_key(parsed: ParsedNVD, row: Dict[str, str], allowlist: Dict[str, str]) -> List[Tuple[str, str, int]]:
    rk, _, _ = effective_repo_from_decision_row(row, allowlist)
    if not rk:
        return []
    cve_id = lower_text(row.get("cve_id")).upper()
    out = []
    for rng in resolve_ranges_for_decision_row(parsed, row):
        out.append((cve_id, rk, rng.range_id))
    return out


# ---------------------------------------------------------------------------
# Base flow, manual flow, codex flow
# ---------------------------------------------------------------------------

def build_base_bindings(
    parsed: ParsedNVD,
    allowlist: Dict[str, str],
    repo_nonproduct_allow: Set[str],
) -> Tuple[Dict[BindingKey, Binding], List[CandidateAudit], List[CandidateAudit], List[CandidateAudit], Counter]:
    stats = Counter()
    bindings: Dict[BindingKey, Binding] = {}
    accepted: List[CandidateAudit] = []
    rejected: List[CandidateAudit] = []
    review: List[CandidateAudit] = []

    for cve_id, refs in parsed.refs_by_cve.items():
        ranges = parsed.ranges_by_cve.get(cve_id, [])
        if not refs or not ranges:
            continue
        for ref in refs:
            if ref.repo_key not in allowlist:
                stats["base:skip_repo_not_allowlisted"] += 1
                continue
            for rng in ranges:
                audit = classify_pair(ref, rng, repo_nonproduct_allow)
                stats[f"base:decision:{audit.decision}"] += 1
                stats[f"base:rule:{audit.decision_rule}"] += 1
                if audit.decision == "accept":
                    accepted.append(audit)
                    add_binding(
                        bindings,
                        stats,
                        cve_id=cve_id,
                        repo_key_value=ref.repo_key,
                        rng=rng,
                        github_url=ref.github_url,
                        decision_source="base_rule",
                        decision_rule=audit.decision_rule,
                        decision_reason=audit.reject_reason,
                    )
                elif audit.decision == "review":
                    review.append(audit)
                else:
                    rejected.append(audit)
    return bindings, accepted, rejected, review, stats


def load_manual_rows(manual_dir: Path) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], Set[str], Counter]:
    stats = Counter()
    accept_rows: List[Dict[str, str]] = []
    reject_rows: List[Dict[str, str]] = []
    repo_nonproduct_allow: Set[str] = set()

    if not manual_dir.exists():
        return accept_rows, reject_rows, repo_nonproduct_allow, stats

    accept_names = [
        "mismatch_or_review_cve_github_pairs_accept.csv",
        "review_inserted_manual_decision_accept.csv",
    ]
    reject_names = [
        "mismatch_or_review_cve_github_pairs_reject.csv",
        "review_inserted_manual_decision_reject.csv",
    ]
    repo_accept_names = [
        "metadata_nonproduct_term_boundary_audit_accept.csv",
    ]

    for n in accept_names:
        for r in read_csv_rows(manual_dir / n):
            r["source_dataset"] = r.get("source_dataset") or n.rsplit(".", 1)[0]
            r["source_file"] = r.get("source_file") or n
            accept_rows.append(r)
        stats[f"manual:read_accept:{n}"] = len([r for r in accept_rows if r.get("source_file") == n])

    for n in reject_names:
        for r in read_csv_rows(manual_dir / n):
            r["source_dataset"] = r.get("source_dataset") or n.rsplit(".", 1)[0]
            r["source_file"] = r.get("source_file") or n
            reject_rows.append(r)
        stats[f"manual:read_reject:{n}"] = len([r for r in reject_rows if r.get("source_file") == n])

    for n in repo_accept_names:
        for r in read_csv_rows(manual_dir / n):
            rk = norm_repo_key(r.get("repo_key") or r.get("git_key") or r.get("repo"))
            if rk and "@" in rk:
                repo_nonproduct_allow.add(rk)
        stats[f"manual:read_repo_accept:{n}"] = len(repo_nonproduct_allow)

    return accept_rows, reject_rows, repo_nonproduct_allow, stats


def apply_decision_rows(
    *,
    stage: str,
    parsed: ParsedNVD,
    allowlist: Dict[str, str],
    bindings: Dict[BindingKey, Binding],
    accept_rows: Sequence[Dict[str, str]],
    reject_rows: Sequence[Dict[str, str]],
    reject_guard_keys: Optional[Set[Tuple[str, str, int]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Counter]:
    stats = Counter()
    applied: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    reject_guard_keys = reject_guard_keys or set()

    # First remove explicit reject rows from current bindings.
    for row in reject_rows:
        rk, _, repo_reason = effective_repo_from_decision_row(row, allowlist)
        if not rk:
            skipped.append({**row, "stage": stage, "action": "reject_skip", "skip_reason": "no_repo"})
            stats[f"{stage}:reject_skip:no_repo"] += 1
            continue
        if rk not in allowlist:
            skipped.append({**row, "stage": stage, "action": "reject_skip", "repo_key_effective": rk, "skip_reason": "repo_not_allowlisted"})
            stats[f"{stage}:reject_skip:repo_not_allowlisted"] += 1
            continue
        n = remove_binding_for_row(bindings, parsed, row, rk, stats)
        if n:
            applied.append({**row, "stage": stage, "action": "reject_removed_binding", "repo_key_effective": rk, "removed_bindings": n})
        else:
            skipped.append({**row, "stage": stage, "action": "reject_no_existing_binding", "repo_key_effective": rk})

    # Then apply accept rows.
    seen_accept_keys: Set[Tuple[str, str, int]] = set()
    for row in accept_rows:
        cve_id = lower_text(row.get("cve_id")).upper()
        if not cve_id:
            skipped.append({**row, "stage": stage, "action": "accept_skip", "skip_reason": "missing_cve_id"})
            stats[f"{stage}:accept_skip:missing_cve_id"] += 1
            continue
        rk, chosen_url, repo_reason = effective_repo_from_decision_row(row, allowlist)
        if not rk:
            skipped.append({**row, "stage": stage, "action": "accept_skip", "skip_reason": "no_repo"})
            stats[f"{stage}:accept_skip:no_repo"] += 1
            continue
        if rk not in allowlist:
            skipped.append({**row, "stage": stage, "action": "accept_skip", "repo_key_effective": rk, "skip_reason": "repo_not_allowlisted"})
            stats[f"{stage}:accept_skip:repo_not_allowlisted"] += 1
            continue

        ranges = resolve_ranges_for_decision_row(parsed, row)
        if not ranges:
            skipped.append({**row, "stage": stage, "action": "accept_skip", "repo_key_effective": rk, "skip_reason": "no_matching_nvd_range"})
            stats[f"{stage}:accept_skip:no_matching_nvd_range"] += 1
            continue

        any_added = False
        for rng in ranges:
            exact = (cve_id, rk, rng.range_id)
            if exact in reject_guard_keys:
                conflicts.append({**row, "stage": stage, "repo_key_effective": rk, "range_id": rng.range_id, "conflict_reason": "exact_key_in_reject_guard"})
                stats[f"{stage}:conflict:reject_guard"] += 1
                continue
            if exact in seen_accept_keys:
                skipped.append({**row, "stage": stage, "action": "accept_skip", "repo_key_effective": rk, "range_id": rng.range_id, "skip_reason": "duplicate_accept_key"})
                stats[f"{stage}:accept_skip:duplicate_accept_key"] += 1
                continue
            seen_accept_keys.add(exact)

            url = chosen_url or as_text(row.get("github_url"))
            original_repo = norm_repo_key(row.get("repo_key"))
            # Redirect/canonical accept must supersede the original repo binding.
            # Otherwise old repo_key refs remain as evidence-only rows with zero version index.
            if original_repo and original_repo != rk and repo_reason in {"canonical_repo_key_allowlisted", "suggested_url_repo_allowlisted"}:
                old_key = BindingKey(cve_id, original_repo, rng.range_id)
                if old_key in bindings:
                    del bindings[old_key]
                    stats[f"{stage}:canonical_replaced_original_binding"] += 1
            is_404 = as_text(row.get("url_http_status")) == "404" or as_text(row.get("github_repo_http_status")) == "404"
            added = add_binding(
                bindings,
                stats,
                cve_id=cve_id,
                repo_key_value=rk,
                rng=rng,
                github_url=url,
                decision_source=stage,
                decision_rule=as_text(row.get("codex_decision") or row.get("input_decision_rule") or "manual_accept"),
                decision_reason=as_text(row.get("decision_reason") or row.get("manual_reason") or row.get("audit_reason") or "accepted decision row"),
                evidence_only=is_404,
                original_repo_key=original_repo,
                original_github_url=as_text(row.get("github_url")),
            )
            if added:
                any_added = True
                applied.append({
                    **row,
                    "stage": stage,
                    "action": "accept_applied",
                    "repo_key_effective": rk,
                    "repo_resolution_reason": repo_reason,
                    "range_id": rng.range_id,
                    "range_key_effective": rng.range_key,
                    "cpe_uri_effective": rng.cpe_uri,
                    "evidence_only": int(is_404),
                })
            else:
                skipped.append({**row, "stage": stage, "action": "accept_skip", "repo_key_effective": rk, "range_id": rng.range_id, "skip_reason": "binding_already_exists"})
        if not any_added:
            stats[f"{stage}:accept_no_new_binding"] += 1

    return applied, skipped, conflicts, stats


# ---------------------------------------------------------------------------
# GitHub cache loading
# ---------------------------------------------------------------------------

def iter_cache_files(cache_dir: Path) -> Iterator[Path]:
    if not cache_dir.exists():
        return
    for p in cache_dir.rglob("*"):
        if p.is_file() and p.name.lower().endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")):
            yield p


def read_jsonish(path: Path) -> Iterator[Any]:
    """
    Robust cache JSON reader.

    This intentionally mirrors the old 02-04 cache loader behavior but also
    supports JSONL/NDJSON and concatenated JSON objects.  The previous v3
    draft accidentally called a removed load_json_file() helper here; because
    the exception was swallowed, every cache file was counted but no version
    rows were loaded.
    """
    try:
        for obj in load_json_or_jsonl(path):
            yield obj
    except Exception as e:
        # Keep old 02-04 behavior: malformed cache files should not abort the
        # whole build, but record why cache parsing skipped them.
        return


def infer_repo_from_path(path: Path) -> str:
    text = str(path)
    m = re.search(r"([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)", text)
    if m:
        return repo_key(m.group(1), m.group(2))
    m = re.search(r"([A-Za-z0-9_.-]+)__([A-Za-z0-9_.-]+)", text)
    if m:
        return repo_key(m.group(1), m.group(2))
    p = parse_github_url(text)
    return p[2] if p else ""


def infer_repo_from_obj(obj: Any) -> str:
    if isinstance(obj, dict):
        for k in ["repo_key", "git_key"]:
            if isinstance(obj.get(k), str):
                return norm_repo_key(obj[k])
        full_name = obj.get("full_name")
        if isinstance(full_name, str) and "/" in full_name:
            return norm_repo_key(full_name)
        repo_obj = obj.get("repository")
        if isinstance(repo_obj, dict):
            fn = repo_obj.get("full_name")
            if isinstance(fn, str) and "/" in fn:
                return norm_repo_key(fn)
    # URL scan fallback.
    urls = find_github_urls(safe_json(obj))
    repos = sorted({parse_github_url(u)[2] for u in urls if parse_github_url(u)})
    if len(repos) == 1:
        return repos[0]
    return ""


def unwrap_payload(obj: Any) -> List[Any]:
    if isinstance(obj, list):
        return obj
    if not isinstance(obj, dict):
        return []
    for k in ["data", "items", "result", "response"]:
        if isinstance(obj.get(k), list):
            return obj[k]
    combined: List[Any] = []
    for k in ["tags", "releases", "commits"]:
        if isinstance(obj.get(k), list):
            combined.extend(obj[k])
    if combined:
        return combined
    return [obj]


def classify_cache_item(item: Dict[str, Any], path: Path) -> str:
    name = path.name.lower()
    if ("release" in name or "releases" in name) and ("tag_name" in item or "name" in item):
        return "release"
    if ("tag" in name or "tags" in name) and "name" in item:
        return "tag"
    if ("commit" in name or "commits" in name) and "sha" in item:
        return "commit"
    if "tag_name" in item:
        return "release"
    if "sha" in item and isinstance(item.get("commit"), dict):
        return "commit"
    if "name" in item and isinstance(item.get("commit"), dict):
        return "tag"
    if "name" in item and "zipball_url" in item:
        return "release"
    return ""


def load_github_cache(cache_dir: Path, target_repos: Set[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Set[str]], Counter]:
    versions: List[Dict[str, Any]] = []
    commits: List[Dict[str, Any]] = []
    files_by_repo: Dict[str, Set[str]] = defaultdict(set)
    seen_versions: Set[Tuple[str, str, str, str]] = set()
    seen_commits: Set[Tuple[str, str]] = set()
    stats = Counter()

    for path in iter_cache_files(cache_dir):
        stats["cache:files_seen"] += 1
        path_repo = infer_repo_from_path(path)
        for obj in read_jsonish(path):
            base_repo = infer_repo_from_obj(obj) or path_repo
            for item in unwrap_payload(obj):
                if not isinstance(item, dict):
                    continue
                rk = infer_repo_from_obj(item) or base_repo
                rk = norm_repo_key(rk)
                if not rk:
                    stats["cache:skip_no_repo"] += 1
                    continue
                if rk not in target_repos:
                    stats["cache:skip_repo_not_selected"] += 1
                    continue
                kind = classify_cache_item(item, path)
                if kind == "release":
                    version_raw = as_text(item.get("tag_name") or item.get("name"))
                    if not version_raw:
                        continue
                    key = (rk, version_raw, "release", as_text(item.get("target_commitish")))
                    if key in seen_versions:
                        continue
                    seen_versions.add(key)
                    versions.append({
                        "repo_key": rk,
                        "version_raw": version_raw,
                        "version_norm": normalize_version_string(version_raw),
                        "source": "release",
                        "commit_sha": as_text(item.get("target_commitish")),
                        "published_at": as_text(item.get("published_at")),
                        "created_at": as_text(item.get("created_at")),
                        "cache_file": str(path),
                        "raw_json": safe_json(item),
                    })
                    files_by_repo[rk].add(str(path))
                    stats["cache:github_release_versions"] += 1
                elif kind == "tag":
                    version_raw = as_text(item.get("name"))
                    if not version_raw:
                        continue
                    commit_sha = ""
                    if isinstance(item.get("commit"), dict):
                        commit_sha = as_text(item["commit"].get("sha"))
                    key = (rk, version_raw, "tag", commit_sha)
                    if key in seen_versions:
                        continue
                    seen_versions.add(key)
                    versions.append({
                        "repo_key": rk,
                        "version_raw": version_raw,
                        "version_norm": normalize_version_string(version_raw),
                        "source": "tag",
                        "commit_sha": commit_sha,
                        "published_at": "",
                        "created_at": "",
                        "cache_file": str(path),
                        "raw_json": safe_json(item),
                    })
                    files_by_repo[rk].add(str(path))
                    stats["cache:github_tag_versions"] += 1
                elif kind == "commit":
                    sha = as_text(item.get("sha"))
                    if not sha:
                        continue
                    key = (rk, sha)
                    if key in seen_commits:
                        continue
                    seen_commits.add(key)
                    commit_obj = item.get("commit") if isinstance(item.get("commit"), dict) else {}
                    date = ""
                    for who in ["committer", "author"]:
                        x = commit_obj.get(who) if isinstance(commit_obj, dict) else None
                        if isinstance(x, dict) and x.get("date"):
                            date = as_text(x.get("date"))
                            break
                    commits.append({
                        "repo_key": rk,
                        "commit_sha": sha,
                        "commit_date": date,
                        "message": as_text(commit_obj.get("message") if isinstance(commit_obj, dict) else ""),
                        "cache_file": str(path),
                        "raw_json": safe_json(item),
                    })
                    files_by_repo[rk].add(str(path))
                    stats["cache:github_commits"] += 1
    return versions, commits, files_by_repo, stats


# ---------------------------------------------------------------------------
# DB writing and index build
# ---------------------------------------------------------------------------

def setup_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = OFF;
        PRAGMA temp_store = MEMORY;

        CREATE TABLE build_summary (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE repositories (
            repo_key TEXT PRIMARY KEY,
            owner TEXT,
            repo TEXT,
            has_github_cache INTEGER DEFAULT 0,
            cache_files_json TEXT
        );

        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            published TEXT,
            last_modified TEXT,
            vuln_status TEXT,
            description TEXT
        );

        CREATE TABLE cve_github_refs (
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

        CREATE TABLE nvd_cpe_ranges (
            range_id INTEGER PRIMARY KEY,
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

        CREATE TABLE github_versions (
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

        CREATE TABLE github_commits (
            repo_key TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            commit_date TEXT,
            message TEXT,
            cache_file TEXT,
            raw_json TEXT,
            PRIMARY KEY (repo_key, commit_sha)
        );

        CREATE TABLE version_cve_index (
            cve_id TEXT NOT NULL,
            repo_key TEXT NOT NULL,
            version_raw TEXT NOT NULL,
            version_norm TEXT,
            version_source TEXT,
            range_id INTEGER,
            cpe_uri TEXT,
            match_reason TEXT,
            github_refs_json TEXT
        );

        CREATE INDEX idx_cgr_cve ON cve_github_refs(cve_id);
        CREATE INDEX idx_cgr_repo ON cve_github_refs(repo_key);
        CREATE INDEX idx_ranges_cve ON nvd_cpe_ranges(cve_id);
        CREATE INDEX idx_ranges_cve_product ON nvd_cpe_ranges(cve_id, vendor, product);
        CREATE INDEX idx_gv_repo ON github_versions(repo_key);
        CREATE INDEX idx_gv_repo_version_raw ON github_versions(repo_key, version_raw);
        CREATE INDEX idx_gv_repo_version_norm ON github_versions(repo_key, version_norm);
        CREATE INDEX idx_vci_repo_version_raw ON version_cve_index(repo_key, version_raw);
        CREATE INDEX idx_vci_repo_version_norm ON version_cve_index(repo_key, version_norm);
        CREATE INDEX idx_vci_cve ON version_cve_index(cve_id);
        CREATE INDEX idx_vci_repo_cve ON version_cve_index(repo_key, cve_id);
        CREATE INDEX idx_vci_repo_cve_range ON version_cve_index(repo_key, cve_id, range_id);
        """
    )


def create_ref_rows_from_bindings(bindings: Dict[BindingKey, Binding]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    # group by cve/repo/url; reference_json contains accepted ranges.
    for b in bindings.values():
        key = (b.cve_id, b.repo_key, b.github_url)
        g = grouped.setdefault(key, {
            "cve_id": b.cve_id,
            "repo_key": b.repo_key,
            "github_url": b.github_url,
            "ref_kind": infer_ref_kind(b.github_url)[0],
            "commit_sha": infer_ref_kind(b.github_url)[1],
            "tag_name": infer_ref_kind(b.github_url)[2],
            "source": b.decision_source,
            "accepted_ranges": [],
            "original_repo_keys": set(),
            "original_github_urls": set(),
            "decision_sources": set(),
            "evidence_only": False,
        })
        g["accepted_ranges"].append({
            "range_id": b.range_id,
            "range_key": b.range_key,
            "vendor": b.vendor,
            "product": b.product,
            "cpe_uri": b.cpe_uri,
            "decision_source": b.decision_source,
            "decision_rule": b.decision_rule,
            "decision_reason": b.decision_reason,
        })
        g["original_repo_keys"].add(b.original_repo_key)
        g["original_github_urls"].add(b.original_github_url)
        g["decision_sources"].add(b.decision_source)
        g["evidence_only"] = bool(g["evidence_only"] or b.evidence_only)
    out: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for key, g in grouped.items():
        ref_json = {
            "accepted_ranges": g.pop("accepted_ranges"),
            "original_repo_keys": sorted(g.pop("original_repo_keys")),
            "original_github_urls": sorted(g.pop("original_github_urls")),
            "decision_sources": sorted(g.pop("decision_sources")),
            "evidence_only": bool(g.pop("evidence_only")),
            "builder": "04_binding_v3",
        }
        g["reference_json"] = safe_json(ref_json)
        out[key] = g
    return out


def build_version_index_rows(
    bindings: Dict[BindingKey, Binding],
    ranges_by_id: Dict[int, CPERange],
    versions_by_repo: Dict[str, List[Dict[str, Any]]],
    refs_by_cve_repo: Dict[Tuple[str, str], List[Dict[str, Any]]],
    stats: Counter,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str, int]] = set()
    bindings_by_repo: Dict[str, List[Binding]] = defaultdict(list)
    for b in bindings.values():
        bindings_by_repo[b.repo_key].append(b)

    for repo, blist in bindings_by_repo.items():
        versions = versions_by_repo.get(repo, [])
        if not versions:
            for b in blist:
                stats["index:skip_no_github_versions"] += 1
                if b.evidence_only:
                    stats["index:evidence_only_no_versions"] += 1
            continue
        for b in blist:
            rng = ranges_by_id.get(b.range_id)
            if not rng:
                stats["index:skip_missing_range"] += 1
                continue
            refs = refs_by_cve_repo.get((b.cve_id, b.repo_key), [])
            refs_json = safe_json([
                {"github_url": r.get("github_url"), "ref_kind": r.get("ref_kind"), "source": r.get("source")}
                for r in refs[:50]
            ])
            for v in versions:
                ok, reason = version_matches_range(v.get("version_raw", ""), rng)
                if not ok:
                    stats[f"index:not_match:{reason}"] += 1
                    continue
                key = (b.cve_id, b.repo_key, v.get("version_raw", ""), b.range_id)
                if key in seen:
                    stats["index:duplicate"] += 1
                    continue
                seen.add(key)
                rows.append({
                    "cve_id": b.cve_id,
                    "repo_key": b.repo_key,
                    "version_raw": v.get("version_raw", ""),
                    "version_norm": v.get("version_norm", ""),
                    "version_source": v.get("source", ""),
                    "range_id": b.range_id,
                    "cpe_uri": rng.cpe_uri,
                    "match_reason": f"{reason};binding_source={b.decision_source}",
                    "github_refs_json": refs_json,
                })
                stats["index:insert_attempt"] += 1
    return rows


def write_final_db(
    db_path: Path,
    parsed: ParsedNVD,
    bindings: Dict[BindingKey, Binding],
    allowlist: Dict[str, str],
    versions: List[Dict[str, Any]],
    commits: List[Dict[str, Any]],
    cache_files_by_repo: Dict[str, Set[str]],
    summary: Counter,
    out_dir: Path,
) -> Counter:
    stats = Counter()
    if db_path.exists():
        db_path.unlink()
    for suffix in ["-wal", "-shm"]:
        p = Path(str(db_path) + suffix)
        if p.exists():
            p.unlink()

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    setup_db(conn)

    ref_rows = create_ref_rows_from_bindings(bindings)
    repo_set = {rk for (_, rk, _) in ref_rows.keys()} | {v["repo_key"] for v in versions}
    repo_set = {rk for rk in repo_set if rk in allowlist}

    # cves to write: accepted/bound CVEs only.
    cve_set = {cve_id for (cve_id, _, _) in ref_rows.keys()} | {b.cve_id for b in bindings.values()}
    # nvd ranges to write: all ranges for accepted CVEs, but version index will use accepted bindings only.
    ranges_to_write: List[CPERange] = []
    for cve_id in sorted(cve_set):
        ranges_to_write.extend(parsed.ranges_by_cve.get(cve_id, []))

    # Filter versions and commits to selected repos only.
    versions = [v for v in versions if v.get("repo_key") in repo_set]
    commits = [c for c in commits if c.get("repo_key") in repo_set]
    versions_by_repo: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for v in versions:
        versions_by_repo[v["repo_key"]].append(v)

    refs_by_cve_repo: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in ref_rows.values():
        refs_by_cve_repo[(row["cve_id"], row["repo_key"])].append(row)

    ranges_by_id = {r.range_id: r for r in ranges_to_write}
    index_rows = build_version_index_rows(bindings, ranges_by_id, versions_by_repo, refs_by_cve_repo, stats)

    with conn:
        for rk in sorted(repo_set):
            owner, repo = split_repo_key(rk)
            files = sorted(cache_files_by_repo.get(rk, set()))
            conn.execute(
                "INSERT INTO repositories(repo_key, owner, repo, has_github_cache, cache_files_json) VALUES (?, ?, ?, ?, ?)",
                (rk, owner, repo, 1 if files else 0, safe_json(files)),
            )
        for cve_id in sorted(cve_set):
            c = parsed.cves.get(cve_id) or CVERow(cve_id=cve_id)
            conn.execute(
                "INSERT INTO cves(cve_id, published, last_modified, vuln_status, description) VALUES (?, ?, ?, ?, ?)",
                (c.cve_id, c.published, c.last_modified, c.vuln_status, c.description),
            )
        for row in ref_rows.values():
            if row["repo_key"] not in allowlist:
                stats["db:skip_ref_repo_not_allowlisted"] += 1
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO cve_github_refs
                (cve_id, repo_key, github_url, ref_kind, commit_sha, tag_name, source, reference_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (row["cve_id"], row["repo_key"], row["github_url"], row["ref_kind"], row["commit_sha"], row["tag_name"], row["source"], row["reference_json"]),
            )
        for r in ranges_to_write:
            conn.execute(
                """
                INSERT INTO nvd_cpe_ranges
                (range_id, cve_id, cpe_uri, part, vendor, product, cpe_version,
                 version_start_including, version_start_excluding, version_end_including, version_end_excluding,
                 vulnerable, match_criteria_id, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (r.range_id, r.cve_id, r.cpe_uri, r.part, r.vendor, r.product, r.cpe_version,
                 r.version_start_including, r.version_start_excluding, r.version_end_including, r.version_end_excluding,
                 r.vulnerable, r.match_criteria_id, r.raw_json),
            )
        conn.executemany(
            """
            INSERT INTO github_versions
            (repo_key, version_raw, version_norm, source, commit_sha, published_at, created_at, cache_file, raw_json)
            VALUES (:repo_key, :version_raw, :version_norm, :source, :commit_sha, :published_at, :created_at, :cache_file, :raw_json)
            """,
            versions,
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO github_commits
            (repo_key, commit_sha, commit_date, message, cache_file, raw_json)
            VALUES (:repo_key, :commit_sha, :commit_date, :message, :cache_file, :raw_json)
            """,
            commits,
        )
        conn.executemany(
            """
            INSERT INTO version_cve_index
            (cve_id, repo_key, version_raw, version_norm, version_source, range_id, cpe_uri, match_reason, github_refs_json)
            VALUES (:cve_id, :repo_key, :version_raw, :version_norm, :version_source, :range_id, :cpe_uri, :match_reason, :github_refs_json)
            """,
            index_rows,
        )

        # Build summary in DB.
        summary.update(stats)
        final_counts = {}
        for t in CORE_TABLES:
            n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            final_counts[f"final_table_rows:{t}"] = n
        for k, v in final_counts.items():
            summary[k] = v
        summary["flow"] = "base_rule -> manual_override -> codex_accept -> range_bound_index -> core_schema_only"
        summary["builder_version"] = "04_binding_v3"
        summary["created_at"] = now_text()
        for k in sorted(summary):
            conn.execute("INSERT OR REPLACE INTO build_summary(key, value) VALUES (?, ?)", (str(k), str(summary[k])))

    quick = conn.execute("PRAGMA quick_check").fetchone()[0]
    if quick != "ok":
        raise RuntimeError(f"SQLite quick_check failed: {quick}")

    # Core schema validation.
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    unexpected = sorted(set(tables) - set(CORE_TABLES))
    missing = sorted(set(CORE_TABLES) - set(tables))
    conn.close()
    if unexpected or missing:
        raise RuntimeError(f"core schema validation failed: unexpected={unexpected}, missing={missing}")

    stats["db:quick_check_ok"] = 1
    return stats


# ---------------------------------------------------------------------------
# Audit exports
# ---------------------------------------------------------------------------

def audit_to_dict(a: CandidateAudit) -> Dict[str, Any]:
    return {
        "cve_id": a.cve_id,
        "github_url": a.github_url,
        "source": a.source,
        "repo_key": a.repo_key,
        "owner": a.owner,
        "repo": a.repo,
        "vendor": a.vendor,
        "product": a.product,
        "cpe_uri": a.cpe_uri,
        "range_key": a.range_key,
        "owner_score": a.owner_score,
        "repo_score": a.repo_score,
        "fitness_score": a.fitness_score,
        "hard_tokens": a.hard_tokens,
        "soft_tokens": a.soft_tokens,
        "decision": a.decision,
        "decision_rule": a.decision_rule,
        "reject_reason": a.reject_reason,
    }


def export_binding_audit(out_dir: Path, bindings: Dict[BindingKey, Binding], versions_by_repo: Optional[Dict[str, int]] = None) -> None:
    rows: List[Dict[str, Any]] = []
    versions_by_repo = versions_by_repo or {}
    for b in bindings.values():
        rows.append({
            "cve_id": b.cve_id,
            "repo_key": b.repo_key,
            "range_id": b.range_id,
            "range_key": b.range_key,
            "vendor": b.vendor,
            "product": b.product,
            "cpe_uri": b.cpe_uri,
            "github_url": b.github_url,
            "decision_source": b.decision_source,
            "decision_rule": b.decision_rule,
            "decision_reason": b.decision_reason,
            "evidence_only": int(b.evidence_only),
            "repo_version_count": versions_by_repo.get(b.repo_key, 0),
            "original_repo_key": b.original_repo_key,
            "original_github_url": b.original_github_url,
        })
    write_csv_rows(out_dir / "final_cve_repo_range_bindings.csv", rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Build final range-bound CVE/GitHub/version SQLite DB without legacy script reuse.")
    ap.add_argument("--nvd-input", required=True, help="NVD filtered JSON path")
    ap.add_argument("--github-cache", required=True, help="GitHub tags/releases/commits cache directory")
    ap.add_argument("--git-dir", required=True, help="git/ directory containing owner@repo allowlist files")
    ap.add_argument("--manual-overrides-dir", default="manual_overrides", help="manual override CSV directory")
    ap.add_argument("--codex-res-dir", default="codex_res", help="directory containing accept_list.csv and reject_list.csv")
    ap.add_argument("--out-workspace", default="workspace_refiltered_v4_binding", help="output workspace")
    ap.add_argument("--out-db-name", default="version_cve_refiltered.db", help="output DB file name")
    ap.add_argument("--force", action="store_true", help="overwrite output workspace/DB")
    ap.add_argument("--write-audit", action="store_true", default=True, help="write audit CSV files")
    args = ap.parse_args()

    nvd_input = Path(args.nvd_input).resolve()
    github_cache = Path(args.github_cache).resolve()
    git_dir = Path(args.git_dir).resolve()
    manual_dir = Path(args.manual_overrides_dir).resolve()
    codex_dir = Path(args.codex_res_dir).resolve()
    out_dir = Path(args.out_workspace).resolve()
    db_path = out_dir / args.out_db_name

    if not nvd_input.exists():
        raise FileNotFoundError(nvd_input)
    if not github_cache.exists():
        raise FileNotFoundError(github_cache)
    if not git_dir.exists():
        raise FileNotFoundError(git_dir)
    if out_dir.exists() and args.force:
        # Preserve external safety: only remove DB/audits generated by this workspace.
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[START] {now_text()}")
    print(f"[INFO] nvd_input={nvd_input}")
    print(f"[INFO] github_cache={github_cache}")
    print(f"[INFO] git_dir={git_dir}")
    print(f"[INFO] out_dir={out_dir}")

    summary = Counter()

    print("[STEP 1] load git allowlist and decision CSVs")
    allowlist = load_git_allowlist(git_dir)
    summary["git_allowlist_repos"] = len(allowlist)
    write_csv_rows(out_dir / "git_sample_allowlist.csv", [
        {"repo_key": rk, "source_file": src} for rk, src in sorted(allowlist.items())
    ])
    print(f"[INFO] allowlist repos={len(allowlist)}")

    manual_accept, manual_reject, repo_nonproduct_allow, manual_load_stats = load_manual_rows(manual_dir)
    summary.update(manual_load_stats)

    codex_accept_path = find_first_existing(codex_dir, ["accept_list.csv", "accept_list_reviewed.csv"])
    codex_reject_path = find_first_existing(codex_dir, ["reject_list.csv", "reject_list_reviewed.csv"])
    codex_accept_rows = read_csv_rows(codex_accept_path) if codex_accept_path else []
    codex_reject_rows = read_csv_rows(codex_reject_path) if codex_reject_path else []
    summary["codex:accept_rows_read"] = len(codex_accept_rows)
    summary["codex:reject_rows_read"] = len(codex_reject_rows)
    print(f"[INFO] manual_accept={len(manual_accept)} manual_reject={len(manual_reject)} repo_nonproduct_allow={len(repo_nonproduct_allow)}")
    print(f"[INFO] codex_accept={len(codex_accept_rows)} codex_reject={len(codex_reject_rows)}")

    print("[STEP 2] parse NVD")
    parsed = parse_nvd(nvd_input)
    summary.update(parsed.stats)
    print(f"[INFO] parsed cves={len(parsed.cves)} ranges={sum(len(v) for v in parsed.ranges_by_cve.values())} cves_with_refs={len(parsed.refs_by_cve)}")

    print("[STEP 3] base rule classification and range-bound accept")
    bindings, base_accept, base_reject, base_review, base_stats = build_base_bindings(parsed, allowlist, repo_nonproduct_allow)
    summary.update(base_stats)
    print(f"[INFO] base accepted={len(base_accept)} rejected={len(base_reject)} review={len(base_review)} bindings={len(bindings)}")

    if args.write_audit:
        write_csv_rows(out_dir / "accepted_candidate_pairs.csv", [audit_to_dict(a) for a in base_accept])
        write_csv_rows(out_dir / "rejected_candidate_pairs.csv", [audit_to_dict(a) for a in base_reject])
        write_csv_rows(out_dir / "review_candidate_pairs.csv", [audit_to_dict(a) for a in base_review])

    print("[STEP 4] apply manual overrides after base rule")
    manual_applied, manual_skipped, manual_conflicts, manual_stats = apply_decision_rows(
        stage="manual_override",
        parsed=parsed,
        allowlist=allowlist,
        bindings=bindings,
        accept_rows=manual_accept,
        reject_rows=manual_reject,
        reject_guard_keys=set(),
    )
    summary.update(manual_stats)
    print(f"[INFO] manual applied={len(manual_applied)} skipped={len(manual_skipped)} conflicts={len(manual_conflicts)} bindings={len(bindings)}")

    print("[STEP 5] apply codex accept/reject after existing-flow stages")
    reject_guard: Set[Tuple[str, str, int]] = set()
    for r in codex_reject_rows:
        for key in decision_exact_key(parsed, r, allowlist):
            reject_guard.add(key)
    summary["codex:reject_guard_exact_keys"] = len(reject_guard)
    codex_actions, codex_skipped, codex_conflicts, codex_stats = apply_decision_rows(
        stage="codex_accept",
        parsed=parsed,
        allowlist=allowlist,
        bindings=bindings,
        accept_rows=codex_accept_rows,
        # Codex reject rows are not inserted into DB, but they must remove/block
        # exact CVE-repo-range bindings that survived base/manual stages.
        reject_rows=codex_reject_rows,
        reject_guard_keys=reject_guard,
    )
    codex_accept_applied = [r for r in codex_actions if r.get("action") == "accept_applied"]
    codex_reject_removed = [r for r in codex_actions if str(r.get("action", "")).startswith("reject_")]
    summary.update(codex_stats)
    summary["codex:accept_applied_rows"] = len(codex_accept_applied)
    summary["codex:reject_removed_or_checked_rows"] = len(codex_reject_removed)
    print(f"[INFO] codex accept_applied={len(codex_accept_applied)} reject_removed_or_checked={len(codex_reject_removed)} skipped={len(codex_skipped)} conflicts={len(codex_conflicts)} bindings={len(bindings)}")

    # Export codex reject audit with exact guard resolution status.
    codex_reject_audit: List[Dict[str, Any]] = []
    removed_by_key = {(r.get("cve_id", "").upper(), r.get("repo_key_effective", ""), str(r.get("range_id", ""))): r for r in codex_reject_removed}
    for r in codex_reject_rows:
        keys = decision_exact_key(parsed, r, allowlist)
        codex_reject_audit.append({
            **r,
            "resolved_exact_key_count": len(keys),
            "action": "reject_guard_and_binding_removal",
        })

    export_dir = out_dir / "codex_res_exports"
    write_csv_rows(export_dir / "codex_accept_applied.csv", codex_accept_applied)
    write_csv_rows(export_dir / "codex_reject_removed_bindings.csv", codex_reject_removed)
    write_csv_rows(export_dir / "codex_accept_skipped.csv", codex_skipped)
    write_csv_rows(export_dir / "codex_accept_conflicts.csv", codex_conflicts)
    write_csv_rows(export_dir / "codex_reject_audit_only.csv", codex_reject_audit)
    write_csv_rows(out_dir / "manual_override_applied.csv", manual_applied)
    write_csv_rows(out_dir / "manual_override_skipped.csv", manual_skipped)
    write_csv_rows(out_dir / "manual_override_conflicts.csv", manual_conflicts)

    print("[STEP 6] load GitHub cache for selected allowlisted repos")
    target_repos = {b.repo_key for b in bindings.values() if b.repo_key in allowlist}
    versions, commits, cache_files_by_repo, cache_stats = load_github_cache(github_cache, target_repos)
    summary.update(cache_stats)
    versions_by_repo_count = Counter(v["repo_key"] for v in versions)
    print(f"[INFO] target_repos={len(target_repos)} versions={len(versions)} commits={len(commits)}")
    if cache_stats:
        for k, v in sorted(cache_stats.items()):
            print(f"[CACHE] {k}={v}")
    if target_repos and not versions:
        raise RuntimeError(
            "GitHub cache loader produced zero versions for selected repos. "
            "Refusing to write an empty version_cve_index DB. "
            "Check github-cache path and cache JSON schema."
        )

    print("[STEP 7] write final DB with range-bound version index")
    export_binding_audit(out_dir, bindings, dict(versions_by_repo_count))
    db_stats = write_final_db(
        db_path=db_path,
        parsed=parsed,
        bindings=bindings,
        allowlist=allowlist,
        versions=versions,
        commits=commits,
        cache_files_by_repo=cache_files_by_repo,
        summary=summary,
        out_dir=out_dir,
    )
    summary.update(db_stats)

    # Standalone summary JSON after DB write.
    summary_path = out_dir / "build_summary.json"
    summary_path.write_text(json.dumps({k: summary[k] for k in sorted(summary)}, indent=2, ensure_ascii=False), encoding="utf-8")
    (export_dir / "codex_accept_apply_summary.json").write_text(json.dumps({
        "accept_rows_read": len(codex_accept_rows),
        "reject_rows_read": len(codex_reject_rows),
        "accept_applied_rows": len(codex_accept_applied),
        "reject_removed_or_checked_rows": len(codex_reject_removed),
        "accept_skipped_rows": len(codex_skipped),
        "accept_conflict_rows": len(codex_conflicts),
        "reject_audit_only_rows": len(codex_reject_audit),
        "final_bindings": len(bindings),
        "notes": [
            "version_cve_index is generated only from accepted CVE-repo-CPE-range bindings.",
            "redirect rows use canonical_repo_key when it is allowlisted.",
            "404 evidence rows are retained as cve_github_refs with accepted range metadata; no fake version rows are generated without GitHub versions.",
            "reject_list is not inserted into the DB; exact reject rows remove/block CVE-repo-range bindings.",
            "all final repo-bearing tables are guarded by git allowlist.",
        ],
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print("[STEP 8] final core schema validation")
    conn = sqlite3.connect(str(db_path))
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    print("[INFO] tables=" + ", ".join(tables))
    for t in CORE_TABLES:
        print(f"[COUNT] {t},{conn.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]}")
    print(f"[quick_check] {conn.execute('PRAGMA quick_check').fetchone()[0]}")
    conn.close()

    print(f"[DONE] DB={db_path}")
    print(f"[DONE] summary={summary_path}")
    print(f"[END] {now_text()}")


if __name__ == "__main__":
    main()
