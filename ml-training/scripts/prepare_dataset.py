import argparse
import sys
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services.url_analyzer import InvalidURL, normalize_url


def load_source(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".xlsx", ".xls"}:
        frame = pd.read_excel(path)
    else:
        frame = pd.read_csv(path)
    columns = {str(column).strip().lower(): column for column in frame.columns}
    url_column = columns.get("url") or columns.get("urls") or columns.get("domain")
    label_column = columns.get("label") or columns.get("labels") or columns.get("type")
    if not url_column or not label_column:
        raise ValueError("Dataset must contain URL and label columns.")
    return frame[[url_column, label_column]].rename(columns={url_column: "url", label_column: "label"})


def prepare_dataset(source: Path, output: Path) -> dict:
    frame = load_source(source)
    initial_rows = len(frame)
    frame["url"] = frame["url"].fillna("").astype(str).str.strip()
    frame["label"] = frame["label"].astype(str).str.strip().str.lower()
    label_map = {"legitimate": 0, "benign": 0, "safe": 0, "0": 0, "phishing": 1, "malicious": 1, "unsafe": 1, "1": 1}
    frame["label"] = frame["label"].map(label_map)
    frame = frame.dropna(subset=["label"])
    frame["label"] = frame["label"].astype(int)
    normalized_urls = []
    valid_rows = []
    for index, row in frame.iterrows():
        try:
            normalized_urls.append(normalize_url(row["url"]))
            valid_rows.append(index)
        except (InvalidURL, TypeError):
            continue
    frame = frame.loc[valid_rows].copy()
    frame["url"] = normalized_urls
    before_dedup = len(frame)
    frame = frame.drop_duplicates(subset=["url"]).sort_values("url").reset_index(drop=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    return {
        "source_rows": initial_rows,
        "cleaned_rows": len(frame),
        "legitimate_count": int((frame["label"] == 0).sum()),
        "phishing_count": int((frame["label"] == 1).sum()),
        "duplicate_rows_removed": before_dedup - len(frame),
        "invalid_rows_removed": initial_rows - len(frame) - (before_dedup - len(frame)),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize URL labels into url,label CSV format.")
    parser.add_argument("--input", type=Path, default=PROJECT_ROOT / "ml-training/datasets/source_phishdataset_balanced.xlsx")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "ml-training/datasets/cleaned_urls.csv")
    arguments = parser.parse_args()
    print(prepare_dataset(arguments.input, arguments.output))
