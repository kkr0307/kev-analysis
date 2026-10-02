"""One-off loader: reads the KEV JSON catalog and upserts every row into
MongoDB so the app can be run with DATA_SOURCE=mongo.

Usage:
    python scripts/import_to_mongo.py [path/to/json]

Reads MONGO_URI / MONGO_DB / MONGO_COLLECTION from the environment (see
.env.example), same as the Flask app.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from pymongo import MongoClient, UpdateOne

from config import Config


def main():
    json_path = sys.argv[1] if len(sys.argv) > 1 else Config.JSON_PATH
    with open(json_path, encoding="utf-8") as f:
        payload = json.load(f)
    records = payload["vulnerabilities"]

    client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
    collection = client[Config.MONGO_DB][Config.MONGO_COLLECTION]

    operations = [
        UpdateOne({"cveID": record["cveID"]}, {"$set": record}, upsert=True)
        for record in records
        if record.get("cveID")
    ]
    if not operations:
        print("No records found to import.")
        return

    result = collection.bulk_write(operations)
    collection.create_index("cveID", unique=True)
    print(
        f"Imported {len(operations)} records into "
        f"{Config.MONGO_DB}.{Config.MONGO_COLLECTION} "
        f"(upserted={result.upserted_count}, modified={result.modified_count})"
    )


if __name__ == "__main__":
    main()
