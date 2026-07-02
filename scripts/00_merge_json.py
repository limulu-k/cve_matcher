#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from importlib.resources import path
import json
import re
from pathlib import Path
from datetime import datetime, timezone
import subprocess

def download_nvd(input_dir: Path):
    """
    NVD JSON 파일을 다운로드한다.
    이미 존재하면 다운로드하지 않는다.
    """
    input_dir.mkdir(parents=True, exist_ok=True)
    (input_dir / "backup").mkdir(parents=True, exist_ok=True)

    for y in range(2002, datetime.now().year + 1):
        file_path = input_dir / f"nvdcve-2.0-{y}.json"
        if not file_path.exists():
            print(f"[+] Downloading: {file_path.name}")
            url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}.json.gz"
            subprocess.run(["wget", "-c", url, "-O", str(file_path) + ".gz"], check=True)
            subprocess.run(["gunzip", "-f", str(file_path) + ".gz"], check=True)
            subprocess.run(["mv", str(file_path)+".gz", str(input_dir)+"/backup/"], check=True)
        else:
            print(f"[=] Already exists: {file_path.name}")

    for idx in path(["modified", "recent"]):
        file_path = input_dir / f"nvdcve-2.0-{idx}.json"
        if not file_path.exists():
            print(f"[+] Downloading: {file_path.name}")
            url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{idx}.json.gz"
            subprocess.run(["wget", "-c", url, "-O", str(file_path) + ".gz"], check=True)
            subprocess.run(["gunzip", "-f", str(file_path) + ".gz"], check=True)
            subprocess.run(["mv", str(file_path)+".gz", str(input_dir)+"/backup/"], check=True)
        else:
            print(f"[=] Already exists: {file_path.name}")

def open_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def detect_nvd_format(data: dict):
    """
    NVD 2.0:
        data["vulnerabilities"]

    NVD 1.1:
        data["CVE_Items"]
    """
    if "vulnerabilities" in data:
        return "2.0"
    if "CVE_Items" in data:
        return "1.1"
    return None


def iter_cve_items(data: dict, fmt: str):
    if fmt == "2.0":
        for item in data.get("vulnerabilities", []):
            yield item

    elif fmt == "1.1":
        for item in data.get("CVE_Items", []):
            yield {
                "cve": item.get("cve", {}),
                "configurations": item.get("configurations", {}),
                "impact": item.get("impact", {}),
                "publishedDate": item.get("publishedDate"),
                "lastModifiedDate": item.get("lastModifiedDate"),
                "_source_format": "NVD_1.1"
            }


def get_cve_id(item: dict):
    """
    NVD 2.0:
        item["cve"]["id"]

    NVD 1.1 converted wrapper:
        item["cve"]["CVE_data_meta"]["ID"]
    """
    cve = item.get("cve", {})

    if "id" in cve:
        return cve.get("id")

    return (
        cve.get("CVE_data_meta", {})
           .get("ID")
    )


def file_sort_key(path: Path):
    """
    연도별 파일을 먼저 읽고, modified/recent는 뒤로 보낸다.

    예:
        nvdcve-2.0-2002.json
        ...
        nvdcve-2.0-2026.json
        nvdcve-2.0-modified.json
        nvdcve-2.0-recent.json
    """
    name = path.name.lower()

    m = re.search(r"-(\d{4})\.json$", name)
    if m:
        return (0, int(m.group(1)), name)

    if "modified" in name:
        return (1, 0, name)

    if "recent" in name:
        return (2, 0, name)

    return (3, 0, name)


def collect_json_files(input_dir: Path):
    """
    gz는 아예 수집하지 않는다.
    json 파일만 수집한다.
    """
    files = list(input_dir.rglob("*.json"))
    return sorted(files, key=file_sort_key)


def main():
    parser = argparse.ArgumentParser(
        description="Merge NVD JSON files into one JSON file. Read .json only, include recent/modified, dedupe by CVE ID."
    )
    parser.add_argument(
        "input_dir",
        help="NVD JSON 파일 다운할 디렉터리"
    )
    parser.add_argument(
        "-o", "--output",
        default="./data/nvd_merged.json",
        help="병합 결과 JSON 파일명"
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir).resolve()
    output_path = Path(args.output).resolve()

    download_nvd(input_dir)


    files = collect_json_files(input_dir)

    if not files:
        raise FileNotFoundError(f"*.json 파일을 찾지 못했습니다: {input_dir}")

    seen_cve_ids = set()

    total_files = 0
    total_input_items = 0
    total_written_items = 0
    skipped_duplicates = 0
    skipped_no_cve_id = 0
    skipped_unsupported = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as out:
        out.write("{\n")
        out.write('  "format": "NVD_CVE",\n')
        out.write('  "version": "2.0-merged",\n')
        out.write(f'  "timestamp": "{datetime.now(timezone.utc).isoformat()}",\n')
        out.write('  "source": "merged NVD JSON files including yearly, modified, and recent feeds",\n')
        out.write('  "dedupe_key": "cve_id",\n')
        out.write('  "vulnerabilities": [\n')

        first = True

        for file_path in files:
            total_files += 1
            print(f"[+] Reading: {file_path.name}")

            try:
                data = open_json(file_path)
            except Exception as e:
                print(f"[!] Failed to read {file_path.name}: {e}")
                continue

            fmt = detect_nvd_format(data)

            if fmt is None:
                print(f"[!] Unsupported NVD JSON structure: {file_path.name}")
                skipped_unsupported += 1
                continue

            file_input_count = 0
            file_written_count = 0
            file_duplicate_count = 0
            file_no_id_count = 0

            for item in iter_cve_items(data, fmt):
                total_input_items += 1
                file_input_count += 1

                cve_id = get_cve_id(item)

                if not cve_id:
                    skipped_no_cve_id += 1
                    file_no_id_count += 1
                    continue

                if cve_id in seen_cve_ids:
                    skipped_duplicates += 1
                    file_duplicate_count += 1
                    continue

                seen_cve_ids.add(cve_id)

                if not first:
                    out.write(",\n")

                json.dump(item, out, ensure_ascii=False)
                first = False

                total_written_items += 1
                file_written_count += 1

            print(
                f"    input={file_input_count}, "
                f"written={file_written_count}, "
                f"duplicates={file_duplicate_count}, "
                f"no_id={file_no_id_count}"
            )

        out.write("\n  ],\n")
        out.write(f'  "totalResults": {total_written_items},\n')
        out.write(f'  "inputFiles": {total_files},\n')
        out.write(f'  "inputItems": {total_input_items},\n')
        out.write(f'  "uniqueCveIds": {len(seen_cve_ids)},\n')
        out.write(f'  "skippedDuplicates": {skipped_duplicates},\n')
        out.write(f'  "skippedNoCveId": {skipped_no_cve_id},\n')
        out.write(f'  "skippedUnsupportedFiles": {skipped_unsupported}\n')
        out.write("}\n")

    print()
    print("[DONE]")
    print(f"Input dir               : {input_dir}")
    print(f"Output file             : {output_path}")
    print(f"Read JSON files          : {total_files}")
    print(f"Input CVE items          : {total_input_items}")
    print(f"Written unique CVEs      : {total_written_items}")
    print(f"Unique CVE IDs           : {len(seen_cve_ids)}")
    print(f"Skipped duplicates       : {skipped_duplicates}")
    print(f"Skipped no CVE ID        : {skipped_no_cve_id}")
    print(f"Skipped unsupported files: {skipped_unsupported}")


if __name__ == "__main__":
    main()