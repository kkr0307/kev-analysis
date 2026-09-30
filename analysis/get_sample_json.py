import csv
import os
from pathlib import Path
import json

analysis_dir = Path(__file__).resolve().parent

data_set =  analysis_dir / "nvdcve-2.0-recent.json"
sample_data = analysis_dir / "sample.json"


with open(data_set, "r", encoding="utf-8") as f:
    file_data = json.load(f)
    sample = file_data["vulnerabilities"][0]

with open(sample_data, "w", encoding="utf-8") as f:
    json.dump(sample, f, indent = 4)