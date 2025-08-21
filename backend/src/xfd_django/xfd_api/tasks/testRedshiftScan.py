import os, sys
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
import django
django.setup()
# --- end bootstrap ---
import csv
from typing import Any, Dict, List
from xfd_api.tasks.redshift_cve_scan import upsert_cve_from_redshift_row
# Direct path to your CSV file
DEFAULT_CSV_PATH = "xfd_api/tasks/redshift_query_20250814143429.csv"
CSV_TO_KEYS = {
    "cvemetadata_cve_id": "cve_id",
    "cvemetadata_assigner_short_name": "assigner",
    "containers_cna_title": "title",
    "containers_cna_descriptions": "descriptions",
    "containers_cna_affected": "affected",
    "containers_cna_metrics": "metrics",
    "containers_cna_problem_types": "problem_types",
    "containers_cna_references": "references",
    "containers_cna_source": "source",
    "containers_adp": "adp",
    "cvemetadata_date_published": "published_at",
    "cvemetadata_date_updated": "modified_at",
}
ORDERED_KEYS = [
    "cve_id",
    "assigner",
    "title",
    "descriptions",
    "affected",
    "metrics",
    "problem_types",
    "references",
    "source",
    "adp",
    "published_at",
    "modified_at",
]

def load_rows_from_csv(csv_path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            mapped = {}
            for csv_col, logical_key in CSV_TO_KEYS.items():
                if csv_col in raw:
                    mapped[logical_key] = raw[csv_col]
                else:
                    # fallback for case-insensitive match
                    val = None
                    for k in raw.keys():
                        if k.lower() == csv_col.lower():
                            val = raw[k]
                            break
                    mapped[logical_key] = val
            rows.append(mapped)
    return rows

def run_csv_ingest(csv_path: str = DEFAULT_CSV_PATH) -> int:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV not found at {csv_path}")
    records = load_rows_from_csv(csv_path)
    processed = 0
    for rec in records:
        upsert_cve_from_redshift_row(rec)
        processed += 1
    return processed

def main() -> int:
    count = run_csv_ingest()
    print(f"CSV ingest processed {count} rows from {DEFAULT_CSV_PATH}")
    return count