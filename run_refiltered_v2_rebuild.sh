#!/usr/bin/env bash
set -Eeuo pipefail

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
ENV_NAME="clovery310"
PROJECT_ROOT="${PROJECT_ROOT:-$HOME/korea_univ/cve_matcher}"

NVD_INPUT="./data/filtered.json"
GITHUB_CACHE="./workspace/github_cache"
GIT_DIR="./git"

OUT_WS="workspace_refiltered_v2"
OUT_DB_NAME="version_cve_refiltered.db"
DB_PATH="${OUT_WS}/${OUT_DB_NAME}"

CSV_DIR="manual_overrides"
BUILDER_SCRIPT="./scripts/02-04_refilteringNbuild_nvd2db.py"
OVERRIDE_SCRIPT="./scripts/02-05_apply_manual_overrides_and_partial_reindex.py"
EXPORT_DIR="${OUT_WS}/manual_override_exports"

LOG_DIR="logs"
TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/refiltered_v2_rebuild_${TS}.log"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "[START] $(date '+%Y-%m-%d %H:%M:%S')"
echo "[INFO] log file: ${LOG_FILE}"
echo "[INFO] project root: ${PROJECT_ROOT}"

# ------------------------------------------------------------
# Error handler
# ------------------------------------------------------------
on_error() {
  local exit_code=$?
  echo
  echo "[ERROR] command failed with exit code ${exit_code}"
  echo "[ERROR] line: ${BASH_LINENO[0]}"
  echo "[ERROR] log file: ${LOG_FILE}"
  echo "[END] $(date '+%Y-%m-%d %H:%M:%S')"
  exit "${exit_code}"
}
trap on_error ERR

# ------------------------------------------------------------
# Enter project
# ------------------------------------------------------------
cd "${PROJECT_ROOT}"
echo "[INFO] current dir: $(pwd)"

# ------------------------------------------------------------
# Input checks
# ------------------------------------------------------------
echo
echo "[STEP 1] input checks"

for p in \
  "${NVD_INPUT}" \
  "${GITHUB_CACHE}" \
  "${GIT_DIR}" \
  "${BUILDER_SCRIPT}" \
  "${OVERRIDE_SCRIPT}" \
  "${CSV_DIR}"
do
  if [ ! -e "${p}" ]; then
    echo "[ERROR] missing path: ${p}"
    exit 1
  fi
  echo "[OK] exists: ${p}"
done

echo
echo "[INFO] manual override files:"
ls -lh "${CSV_DIR}" || true

# ------------------------------------------------------------
# STEP 2: Rebuild base DB
# ------------------------------------------------------------
echo
echo "[STEP 2] rebuild base DB with 02-04"
echo "[CMD] python ${BUILDER_SCRIPT} --nvd-input ${NVD_INPUT} --github-cache ${GITHUB_CACHE} --git-dir ${GIT_DIR} --out-workspace ${OUT_WS} --out-db-name ${OUT_DB_NAME} --force --write-audit"

python "${BUILDER_SCRIPT}" \
  --nvd-input "${NVD_INPUT}" \
  --github-cache "${GITHUB_CACHE}" \
  --git-dir "${GIT_DIR}" \
  --out-workspace "${OUT_WS}" \
  --out-db-name "${OUT_DB_NAME}" \
  --force \
  --write-audit

# ------------------------------------------------------------
# STEP 3: quick_check after 02-04
# ------------------------------------------------------------
echo
echo "[STEP 3] sqlite quick_check after 02-04"

if [ ! -f "${DB_PATH}" ]; then
  echo "[ERROR] DB not created: ${DB_PATH}"
  exit 1
fi

CHECK_RESULT="$(sqlite3 "${DB_PATH}" "PRAGMA quick_check;")"
echo "[quick_check] ${CHECK_RESULT}"

if [ "${CHECK_RESULT}" != "ok" ]; then
  echo "[ERROR] SQLite quick_check failed after 02-04"
  exit 1
fi

# ------------------------------------------------------------
# STEP 4: Apply manual overrides and partial reindex
# ------------------------------------------------------------
echo
echo "[STEP 4] apply manual overrides and partial reindex with 02-05"
echo "[CMD] python ${OVERRIDE_SCRIPT} --db ${DB_PATH} --csv-dir ${CSV_DIR} --builder-script ${BUILDER_SCRIPT} --github-cache ${GITHUB_CACHE} --nvd-input ${NVD_INPUT} --refresh-affected-ranges --backup --export-dir ${EXPORT_DIR}"

python "${OVERRIDE_SCRIPT}" \
  --db "${DB_PATH}" \
  --csv-dir "${CSV_DIR}" \
  --builder-script "${BUILDER_SCRIPT}" \
  --github-cache "${GITHUB_CACHE}" \
  --nvd-input "${NVD_INPUT}" \
  --refresh-affected-ranges \
  --backup \
  --export-dir "${EXPORT_DIR}"

# ------------------------------------------------------------
# STEP 5: quick_check after 02-05
# ------------------------------------------------------------
echo
echo "[STEP 5] sqlite quick_check after 02-05"

CHECK_RESULT="$(sqlite3 "${DB_PATH}" "PRAGMA quick_check;")"
echo "[quick_check] ${CHECK_RESULT}"

if [ "${CHECK_RESULT}" != "ok" ]; then
  echo "[ERROR] SQLite quick_check failed after 02-05"
  exit 1
fi

# ------------------------------------------------------------
# STEP 6: Summary
# ------------------------------------------------------------
echo
echo "[STEP 6] summary"

sqlite3 -header -csv "${DB_PATH}" "
SELECT 'repositories' AS table_name, COUNT(*) AS rows FROM repositories
UNION ALL
SELECT 'cves', COUNT(*) FROM cves
UNION ALL
SELECT 'cve_github_refs', COUNT(*) FROM cve_github_refs
UNION ALL
SELECT 'nvd_cpe_ranges', COUNT(*) FROM nvd_cpe_ranges
UNION ALL
SELECT 'github_versions', COUNT(*) FROM github_versions
UNION ALL
SELECT 'github_commits', COUNT(*) FROM github_commits
UNION ALL
SELECT 'version_cve_index', COUNT(*) FROM version_cve_index;
"

echo
echo "[INFO] output DB: ${DB_PATH}"
echo "[INFO] export dir: ${EXPORT_DIR}"
echo "[INFO] log file: ${LOG_FILE}"
echo "[DONE] $(date '+%Y-%m-%d %H:%M:%S')"


# ------------------------------------------------------------
# STEP 5.5: Prune manual/fix auxiliary tables from final DB
# ------------------------------------------------------------
echo
echo "[STEP 5.5] prune manual/fix auxiliary tables"

sqlite3 "${DB_PATH}" <<'SQL'
PRAGMA foreign_keys=OFF;

BEGIN;

DROP TABLE IF EXISTS manual_cve_repo_accept_overrides;
DROP TABLE IF EXISTS manual_cve_repo_reject_overrides;
DROP TABLE IF EXISTS manual_fix_deleted_cve_github_refs;
DROP TABLE IF EXISTS manual_fix_inserted_cve_github_refs;
DROP TABLE IF EXISTS manual_keep_cve_repo_ref;
DROP TABLE IF EXISTS manual_product_line_allow;
DROP TABLE IF EXISTS manual_repo_accept_overrides;

COMMIT;

VACUUM;
PRAGMA quick_check;
SQL

echo "[INFO] remaining tables:"
sqlite3 -readonly "${DB_PATH}" ".tables"

UNEXPECTED_TABLES="$(sqlite3 -readonly "${DB_PATH}" "
WITH allowed(name) AS (
  VALUES
    ('build_summary'),
    ('cve_github_refs'),
    ('cves'),
    ('github_commits'),
    ('github_versions'),
    ('nvd_cpe_ranges'),
    ('repositories'),
    ('version_cve_index')
)
SELECT name
FROM sqlite_master
WHERE type = 'table'
  AND name NOT LIKE 'sqlite_%'
  AND name NOT IN (SELECT name FROM allowed)
ORDER BY name;
")"

if [ -n "${UNEXPECTED_TABLES}" ]; then
  echo "[ERROR] unexpected tables remain:"
  echo "${UNEXPECTED_TABLES}"
  exit 1
fi

echo "[OK] final DB contains only core query tables"