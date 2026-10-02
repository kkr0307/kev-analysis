"""Loads the CISA KEV catalog (from JSON or MongoDB) into a pandas DataFrame,
builds the derived columns the API needs, and exposes the aggregation /
search helpers used by routes/api.py.
"""
import ast
import json
import os

import pandas as pd

from config import Config

RAW_COLUMNS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
]

LIST_COLUMNS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "dueDate",
    "knownRansomwareCampaignUse",
]

RESPONSE_TIME_BUCKETS = [
    ("0-7", 0, 7),
    ("8-14", 8, 14),
    ("15-30", 15, 30),
    ("31-60", 31, 60),
    ("61+", 61, None),
]

_cache = {"df": None}


def _parse_cwes(value):
    """cwes may arrive as 'CWE-79, CWE-89', a single 'CWE-79', a stringified
    Python list "['CWE-79']" (some MongoDB/JSON exports), or an actual list
    (when the source already hands back native lists, e.g. MongoDB)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, (list, tuple)):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except (ValueError, SyntaxError):
            text = text.strip("[]")
    return [part.strip() for part in text.split(",") if part.strip()]


def _load_from_json(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"KEV JSON file not found: {path}")
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    return pd.DataFrame(payload["vulnerabilities"])


def _load_from_mongo(uri, db_name, collection_name):
    from pymongo import MongoClient

    client = MongoClient(uri, serverSelectionTimeoutMS=2000)
    collection = client[db_name][collection_name]
    records = list(collection.find({}, {"_id": 0}))
    return pd.DataFrame(records)


def load_raw_dataframe():
    """The JSON file in data/ is the primary source; MongoDB is used as a
    fallback whenever the JSON is missing (desktop-friendly: works with zero
    setup)."""
    if Config.DATA_SOURCE == "mongo":
        df = _load_from_mongo(Config.MONGO_URI, Config.MONGO_DB, Config.MONGO_COLLECTION)
    else:
        try:
            df = _load_from_json(Config.JSON_PATH)
            if df.empty:
                raise RuntimeError("JSON file is empty")
        except Exception as exc:
            print(f"[kev_analysis] JSON unavailable ({exc}); falling back to MongoDB: {Config.MONGO_URI}")
            df = _load_from_mongo(Config.MONGO_URI, Config.MONGO_DB, Config.MONGO_COLLECTION)

    for col in RAW_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df.fillna("")
    return df


def preprocess(df):
    df = df.copy()

    cwes_raw = df["cwes"]
    for col in RAW_COLUMNS:
        if col != "cwes":
            df[col] = df[col].astype(str)

    df["dateAddedDt"] = pd.to_datetime(df["dateAdded"], errors="coerce")
    df["dueDateDt"] = pd.to_datetime(df["dueDate"], errors="coerce")
    df["responseDays"] = (df["dueDateDt"] - df["dateAddedDt"]).dt.days
    df["year"] = df["dateAddedDt"].dt.year
    df["month"] = df["dateAddedDt"].dt.strftime("%Y-%m").fillna("")
    df["ransomwareFlag"] = df["knownRansomwareCampaignUse"].apply(
        lambda x: 1 if str(x).strip().lower() == "known" else 0
    )
    df["cweList"] = cwes_raw.apply(_parse_cwes)
    df["cweCount"] = df["cweList"].apply(len)
    return df


def get_dataframe(force_reload=False):
    if _cache["df"] is None or force_reload:
        _cache["df"] = preprocess(load_raw_dataframe())
    return _cache["df"]


def get_summary(df=None):
    df = df if df is not None else get_dataframe()
    total = int(len(df))
    vendors = int(df.loc[df["vendorProject"] != "", "vendorProject"].nunique())
    products = int(df.loc[df["product"] != "", "product"].nunique())
    ransomware_known = int(
        (df["knownRansomwareCampaignUse"].str.strip().str.lower() == "known").sum()
    )
    valid_response = df["responseDays"].dropna()
    average_response_days = float(round(valid_response.mean(), 1)) if not valid_response.empty else 0.0
    return {
        "total": total,
        "vendors": vendors,
        "products": products,
        "ransomwareKnown": ransomware_known,
        "averageResponseDays": average_response_days,
    }


def get_trends(df=None):
    df = df if df is not None else get_dataframe()
    valid = df[df["month"] != ""]
    counts = valid.groupby("month").size().sort_index()
    return [{"month": month, "count": int(count)} for month, count in counts.items()]


def get_vendor_stats(df=None, limit=None):
    df = df if df is not None else get_dataframe()
    counts = df.loc[df["vendorProject"] != "", "vendorProject"].value_counts()
    if limit:
        counts = counts.head(limit)
    return [{"vendor": vendor, "count": int(count)} for vendor, count in counts.items()]


def get_product_stats(df=None, limit=None):
    df = df if df is not None else get_dataframe()
    counts = df.loc[df["product"] != "", "product"].value_counts()
    if limit:
        counts = counts.head(limit)
    return [{"product": product, "count": int(count)} for product, count in counts.items()]


def get_cwe_stats(df=None, limit=None):
    df = df if df is not None else get_dataframe()
    exploded = df["cweList"].explode().dropna()
    exploded = exploded[exploded.astype(str).str.strip() != ""]
    counts = exploded.value_counts()
    if limit:
        counts = counts.head(limit)
    return [{"cwe": cwe, "count": int(count)} for cwe, count in counts.items()]


def get_ransomware_stats(df=None):
    df = df if df is not None else get_dataframe()
    counts = df["knownRansomwareCampaignUse"].value_counts()
    result = [
        {"status": "Known", "count": int(counts.get("Known", 0))},
        {"status": "Unknown", "count": int(counts.get("Unknown", 0))},
    ]
    for status, count in counts.items():
        if status not in ("Known", "Unknown") and status:
            result.append({"status": status, "count": int(count)})
    return result


def get_response_time_stats(df=None):
    df = df if df is not None else get_dataframe()
    valid = df["responseDays"].dropna()
    valid = valid[valid >= 0]
    result = []
    for label, low, high in RESPONSE_TIME_BUCKETS:
        mask = (valid >= low) if high is None else ((valid >= low) & (valid <= high))
        result.append({"range": label, "count": int(mask.sum())})
    return result


def get_filter_options(df=None):
    df = df if df is not None else get_dataframe()
    vendors = sorted({v for v in df["vendorProject"] if v})
    years = sorted({int(y) for y in df["year"].dropna().unique()}, reverse=True)
    return {"vendors": vendors, "years": years}


def search_vulnerabilities(df=None, keyword=None, vendor=None, ransomware=None, year=None):
    df = df if df is not None else get_dataframe()
    result = df

    if keyword and keyword.strip():
        kw = keyword.strip().lower()
        searchable = ["cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription"]
        mask = pd.Series(False, index=result.index)
        for col in searchable:
            mask = mask | result[col].str.lower().str.contains(kw, na=False, regex=False)
        result = result[mask]

    if vendor and vendor.strip().lower() != "all":
        result = result[result["vendorProject"].str.lower() == vendor.strip().lower()]

    if ransomware and ransomware.strip().lower() != "all":
        result = result[result["knownRansomwareCampaignUse"].str.lower() == ransomware.strip().lower()]

    if year and str(year).strip().lower() != "all":
        try:
            year_int = int(year)
            result = result[result["year"] == year_int]
        except (TypeError, ValueError):
            pass

    result = result.sort_values("dateAddedDt", ascending=False, na_position="last")
    return result[LIST_COLUMNS].to_dict(orient="records")


def get_vulnerability_detail(cve_id, df=None):
    df = df if df is not None else get_dataframe()
    if not cve_id:
        return None
    match = df[df["cveID"].str.lower() == cve_id.strip().lower()]
    if match.empty:
        return None
    row = match.iloc[0]
    response_days = row["responseDays"]
    return {
        "cveID": row["cveID"],
        "vendorProject": row["vendorProject"],
        "product": row["product"],
        "vulnerabilityName": row["vulnerabilityName"],
        "dateAdded": row["dateAdded"],
        "dueDate": row["dueDate"],
        "responseDays": None if pd.isna(response_days) else int(response_days),
        "knownRansomwareCampaignUse": row["knownRansomwareCampaignUse"],
        "shortDescription": row["shortDescription"],
        "requiredAction": row["requiredAction"],
        "notes": row["notes"],
        "cwes": row["cweList"],
    }
