#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def split_repo_key(repo_key: str) -> Tuple[str, str]:
    repo_key = repo_key.strip().lower().replace("/", "@")
    if "@" not in repo_key:
        return "", ""
    owner, repo = repo_key.split("@", 1)
    return owner, repo


def cache_path(cache_dir: Path, repo_key: str, kind: str, page: int) -> Path:
    owner, repo = split_repo_key(repo_key)
    return cache_dir / f"{owner}__{repo}__{kind}__page_{page}.json"


def load_missing_repos(csv_path: Path, limit: int = 0) -> List[str]:
    repos = []

    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rk = row.get("repo_key")
            if not rk:
                continue

            repos.append(rk.strip().lower())

            if limit and len(repos) >= limit:
                break

    return sorted(set(repos))


def github_get_json(url: str, token: str = "", sleep_sec: float = 0.2):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "cve-version-db-cache-fetcher",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
        text = data.decode("utf-8", errors="replace")
        return json.loads(text), dict(resp.headers)


def fetch_paged(repo_key: str, kind: str, cache_dir: Path, token: str, max_pages: int, per_page: int, sleep_sec: float, force: bool):
    owner, repo = split_repo_key(repo_key)

    if not owner or not repo:
        return {
            "repo_key": repo_key,
            "kind": kind,
            "status": "bad_repo_key",
            "pages_written": 0,
            "error": "bad repo_key",
        }

    pages_written = 0

    for page in range(1, max_pages + 1):
        out = cache_path(cache_dir, repo_key, kind, page)

        if out.exists() and not force:
            pages_written += 1

            # 기존 page가 빈 배열이거나 마지막 page일 수 있으므로 다음 page가 있는지는 모름.
            # 보수적으로 다음 page까지 확인하지 않고 기존 cache는 유지.
            continue

        url = f"https://api.github.com/repos/{owner}/{repo}/{kind}?per_page={per_page}&page={page}"

        try:
            obj, headers = github_get_json(url, token=token, sleep_sec=sleep_sec)
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")[:1000]
            return {
                "repo_key": repo_key,
                "kind": kind,
                "status": f"http_error_{e.code}",
                "pages_written": pages_written,
                "error": err,
            }
        except Exception as e:
            return {
                "repo_key": repo_key,
                "kind": kind,
                "status": "error",
                "pages_written": pages_written,
                "error": str(e),
            }

        with out.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)

        pages_written += 1

        # 빈 배열이면 마지막 page
        if isinstance(obj, list) and len(obj) == 0:
            break

        # per_page보다 적으면 마지막 page
        if isinstance(obj, list) and len(obj) < per_page:
            break

        time.sleep(sleep_sec)

    return {
        "repo_key": repo_key,
        "kind": kind,
        "status": "ok",
        "pages_written": pages_written,
        "error": "",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--missing-csv", required=True)
    ap.add_argument("--cache-dir", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-pages", type=int, default=20)
    ap.add_argument("--per-page", type=int, default=100)
    ap.add_argument("--sleep", type=float, default=0.2)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    ap.add_argument("--log", default="workspace/cache_coverage_audit/fetch_missing_log.csv")
    args = ap.parse_args()

    missing_csv = Path(args.missing_csv).resolve()
    cache_dir = Path(args.cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)

    repos = load_missing_repos(missing_csv, limit=args.limit)

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] repos_to_fetch={len(repos)}")
    print(f"[INFO] cache_dir={cache_dir}")
    print(f"[INFO] token={'yes' if args.token else 'no'}")

    with log_path.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["repo_key", "kind", "status", "pages_written", "error"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for i, rk in enumerate(repos, 1):
            print(f"[{i}/{len(repos)}] {rk}")

            for kind in ["tags", "releases"]:
                res = fetch_paged(
                    repo_key=rk,
                    kind=kind,
                    cache_dir=cache_dir,
                    token=args.token,
                    max_pages=args.max_pages,
                    per_page=args.per_page,
                    sleep_sec=args.sleep,
                    force=args.force,
                )
                writer.writerow(res)
                f.flush()

                if res["status"].startswith("http_error_403"):
                    print("[WARN] 403 rate limit or forbidden. Stop.")
                    return

            time.sleep(args.sleep)

    print(f"[DONE] log={log_path}")


if __name__ == "__main__":
    main()
