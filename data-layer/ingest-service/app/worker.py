import json
import os
from datetime import datetime
from typing import Any, Dict, List

import httpx
from redis.asyncio import Redis

QUEUE_KEY = os.getenv("INGEST_QUEUE_KEY", "ingest:jobs")
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_INDEX = os.getenv("UPLOADS_INDEX", "uploads-raw")


async def _ensure_index(client: httpx.AsyncClient):
    # Create index if not exists (ignore errors)
    await client.put(f"{ES_URL}/{ES_INDEX}", json={
        "mappings": {
            "properties": {
                "upload_id": {"type": "keyword"},
                "ingested_at": {"type": "date"},
                "filename": {"type": "keyword"},
            }
        }
    })


def _read_json_file(path: str) -> List[Dict[str, Any]]:
    # supports: single JSON object OR list of objects OR NDJSON (one json per line)
    docs: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()

    if not content:
        return docs

    # try normal json
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    docs.append(item)
        elif isinstance(parsed, dict):
            docs.append(parsed)
        else:
            docs.append({"value": parsed})
        return docs
    except Exception:
        pass

    # fallback NDJSON
    docs = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    docs.append(obj)
                else:
                    docs.append({"value": obj})
            except Exception:
                docs.append({"raw_line": line})
    return docs


def _read_csv_file(path: str) -> List[Dict[str, Any]]:
    import csv
    docs: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            docs.append(dict(row))
    return docs


async def _bulk_index(client: httpx.AsyncClient, docs: List[Dict[str, Any]]):
    if not docs:
        return {"indexed": 0}

    # Bulk format: action line + source line
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {}}))
        lines.append(json.dumps(d, ensure_ascii=False))
    body = "\n".join(lines) + "\n"

    r = await client.post(
        f"{ES_URL}/{ES_INDEX}/_bulk",
        content=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
    )
    r.raise_for_status()
    data = r.json()
    errors = data.get("errors", False)
    return {"indexed": len(docs), "errors": errors}


async def worker_loop(redis: Redis):
    async with httpx.AsyncClient(timeout=30.0) as client:
        await _ensure_index(client)

        while True:
            # BRPOP blocks until item available
            item = await redis.brpop(QUEUE_KEY, timeout=0)
            if not item:
                continue

            _key, payload_str = item
            try:
                job = json.loads(payload_str)
            except Exception:
                continue

            upload_id = job.get("upload_id")
            path = job.get("path")
            ext = job.get("ext")
            filename = job.get("filename")

            try:
                if not path or not os.path.exists(path):
                    continue

                if ext == ".json":
                    docs = _read_json_file(path)
                elif ext == ".csv":
                    docs = _read_csv_file(path)
                else:
                    docs = [{"raw_path": path}]

                # enrich docs with metadata
                now = datetime.utcnow().isoformat() + "Z"
                enriched = []
                for d in docs:
                    if not isinstance(d, dict):
                        d = {"value": d}
                    d["upload_id"] = upload_id
                    d["filename"] = filename
                    d["ingested_at"] = now
                    enriched.append(d)

                await _bulk_index(client, enriched)

            except Exception as e:
                # keep it simple for now: print error
                print(f"[worker] failed job upload_id={upload_id} err={e}")
                continue
