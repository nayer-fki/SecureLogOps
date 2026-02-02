# app/upload_worker.py
import os
import json
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
from redis.asyncio import Redis

QUEUE_KEY = os.getenv("INGEST_QUEUE_KEY", "ingest:jobs")
DLQ_KEY = os.getenv("REDIS_DLQ_KEY", "ingest:dlq")

# ✅ index audit raw uploads
UPLOADS_INDEX = os.getenv("UPLOADS_INDEX", "uploads-raw")

ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "")

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "8"))
BASE_BACKOFF_MS = int(os.getenv("BASE_BACKOFF_MS", "250"))


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jsonl_bulk(actions: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for a in actions:
        meta = {"index": {"_index": a["_index"]}}
        lines.append(json.dumps(meta, ensure_ascii=False))
        lines.append(json.dumps(a["_source"], ensure_ascii=False))
    return "\n".join(lines) + "\n"


async def _ensure_index(client: httpx.AsyncClient, index_name: str, mappings: Dict[str, Any]) -> None:
    """
    Create index if it does not exist. If exists, ignore.
    Note: Existing mappings won't be overwritten (ES limitation).
    """
    r = await client.put(
        f"{ES_URL}/{index_name}",
        json={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": mappings,
        },
    )
    if r.status_code in (200, 201):
        return
    if r.status_code == 400 and "resource_already_exists_exception" in r.text:
        return
    r.raise_for_status()


async def _bulk_index(client: httpx.AsyncClient, index_name: str, docs: List[Dict[str, Any]]) -> None:
    if not docs:
        return
    ndjson = _jsonl_bulk([{"_index": index_name, "_source": d} for d in docs])
    r = await client.post(
        f"{ES_URL}/_bulk",
        content=ndjson,
        headers={"Content-Type": "application/x-ndjson"},
    )
    r.raise_for_status()
    out = r.json()
    if out.get("errors"):
        sample = out.get("items", [])[:3]
        raise RuntimeError(f"bulk errors=true sample={json.dumps(sample, ensure_ascii=False)[:1500]}")


def _read_jsonl_lines(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _read_file(path: str) -> Any:
    """
    Read JSON / JSONL / NDJSON / CSV.
    - JSON يمكن يكون object أو array
    - JSONL/NDJSON = list of json objects (line by line)
    """
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                # ✅ if it's actually JSONL but renamed .json
                if "Extra data" in str(e):
                    return _read_jsonl_lines(path)
                raise

    if path.endswith(".jsonl") or path.endswith(".ndjson"):
        return _read_jsonl_lines(path)

    if path.endswith(".csv"):
        import csv
        rows: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(dict(row))
        return rows

    # fallback raw text
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {"message": f.read(), "@timestamp": _utc_now_iso()}


def _to_log_docs(payload: Any) -> List[Dict[str, Any]]:
    """
    Dataset index: نكتب logs كما هي باش correlation يقرى message/@timestamp...
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        return [payload]
    return [{"message": str(payload), "@timestamp": _utc_now_iso()}]


def _build_audit_docs(job: Dict[str, Any], payload: Any) -> List[Dict[str, Any]]:
    """
    Audit index uploads-raw: meta + raw
    IMPORTANT: payload هنا لازم يكون الأصلي (قبل ما نبدلوه/log enrich)
    """
    base = {
        "upload_id": job.get("upload_id"),
        "filename": job.get("filename"),
        "stored_name": job.get("stored_name"),
        "path": job.get("path"),
        "ext": job.get("ext"),
        "content_type": job.get("content_type"),
        "size_bytes": job.get("size_bytes"),
        "created_at": job.get("created_at"),
        "ingested_at": _utc_now_iso(),
        "dataset": job.get("dataset"),
        "source": job.get("source"),
    }

    if isinstance(payload, list):
        return [{**base, "raw": item} for item in payload]
    if isinstance(payload, dict):
        return [{**base, "raw": payload}]
    return [{**base, "raw": {"value": payload}}]


async def _process_job(client: httpx.AsyncClient, job: Dict[str, Any]) -> None:
    rel_path = job.get("path") or ""
    abs_path = rel_path if rel_path.startswith("/") else os.path.join("/app", rel_path)

    if not os.path.exists(abs_path):
        alt = os.path.join("/app", UPLOAD_DIR, job.get("stored_name", ""))
        if os.path.exists(alt):
            abs_path = alt
        else:
            raise FileNotFoundError(f"upload file not found: {abs_path} (alt tried {alt})")

    payload = _read_file(abs_path)

    # ✅ KEEP ORIGINAL for audit (do not mutate)
    payload_for_audit = payload

    # ✅ 1) Index logs in dataset (for correlation)
    dataset = job.get("dataset") or "logs-test"
    log_docs = _to_log_docs(payload)

    # ✅ enrich ONLY log_docs (not payload_for_audit)
    src = job.get("source") or "manual_upload"
    for d in log_docs:
        if not isinstance(d, dict):
            continue
        d.setdefault("event", {})
        # ensure event is object
        if not isinstance(d.get("event"), dict):
            d["event"] = {}
        d["event"]["ingest_source"] = src

    await _bulk_index(client, dataset, log_docs)

    # ✅ 2) Index audit raw (BEST EFFORT)
    audit_docs = _build_audit_docs(job, payload_for_audit)
    try:
        await _bulk_index(client, UPLOADS_INDEX, audit_docs)
    except Exception as e:
        # ✅ do NOT fail the job (avoid retries => avoid duplicates)
        print(
            f"[upload-worker] audit_index_failed upload_id={job.get('upload_id')} "
            f"index={UPLOADS_INDEX} err={repr(e)}",
            flush=True,
        )


async def upload_worker_loop(redis: Redis) -> None:
    auth = (ES_USER, ES_PASS) if ES_USER and ES_PASS else None
    timeout = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=30.0)

    async with httpx.AsyncClient(auth=auth, timeout=timeout) as client:
        # ✅ ensure audit index exists (if already exists with old mapping, won't overwrite)
        await _ensure_index(
            client,
            UPLOADS_INDEX,
            {
                "properties": {
                    "upload_id": {"type": "keyword"},
                    "filename": {"type": "keyword"},
                    "stored_name": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "ext": {"type": "keyword"},
                    "content_type": {"type": "keyword"},
                    "size_bytes": {"type": "long"},
                    "created_at": {"type": "date"},
                    "ingested_at": {"type": "date"},
                    "dataset": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    # raw object (good for new index); old index may differ -> best-effort handles it
                    "raw": {"type": "object", "enabled": True},
                }
            },
        )

        print(f"[upload-worker] started. queue={QUEUE_KEY} audit_index={UPLOADS_INDEX}", flush=True)

        while True:
            item = await redis.blpop(QUEUE_KEY, timeout=5)
            if not item:
                await asyncio.sleep(0.2)
                continue

            _, raw = item
            job = json.loads(raw)

            upload_id = job.get("upload_id", "n/a")
            try:
                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        await _process_job(client, job)
                        print(
                            f"[upload-worker] processed upload_id={upload_id} dataset={job.get('dataset')}",
                            flush=True,
                        )
                        break
                    except Exception as e:
                        if attempt == MAX_RETRIES:
                            raise
                        backoff = (BASE_BACKOFF_MS * (2 ** (attempt - 1))) / 1000.0
                        print(
                            f"[upload-worker] retry {attempt}/{MAX_RETRIES} upload_id={upload_id} "
                            f"err={repr(e)} backoff={backoff}s",
                            flush=True,
                        )
                        await asyncio.sleep(backoff)

            except Exception as e:
                await redis.rpush(DLQ_KEY, json.dumps({"job": job, "error": repr(e)}))
                print(f"[upload-worker] failed upload_id={upload_id} err={repr(e)}", flush=True)
