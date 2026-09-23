import argparse
import json
from pathlib import Path

import pandas as pd

from train_models import train


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate and refresh the phishing model artifacts.")
    parser.add_argument("--input", type=Path, default=Path("ml-training/datasets/cleaned_urls.csv"))
    arguments = parser.parse_args()
    metadata = train(
        arguments.input,
        Path("ml-training/models"),
        Path("ml-training/reports"),
        Path("backend/app/ml/phishing_model.joblib"),
    )
    print(json.dumps(metadata, indent=2))
