# app/api/routes/uploads.py
from fastapi import APIRouter, UploadFile, File, HTTPException, Request, Form
from datetime import datetime, timezone
import os
import uuid
import shutil
import json

router = APIRouter(prefix="", tags=["uploads"])

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
QUEUE_KEY = os.getenv("INGEST_QUEUE_KEY", "ingest:jobs")
MAX_MB = int(os.getenv("UPLOAD_MAX_MB", "25"))

# ✅ دعم JSONL/NDJSON زادة
ALLOWED_EXT = {".csv", ".json", ".jsonl", ".ndjson"}

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

@router.post("/uploads")
async def upload_logs(
    request: Request,
    file: UploadFile = File(...),
    # ✅ نخليوهم optional (بالـ default)
    dataset: str = Form("logs-test"),
    source: str = Form("manual_upload"),
):
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(status_code=400, detail="Only .csv, .json, .jsonl, .ndjson allowed")

    upload_id = str(uuid.uuid4())
    safe_name = file.filename.replace("/", "_").replace("\\", "_")
    stored_name = f"{upload_id}_{safe_name}"
    path = os.path.join(UPLOAD_DIR, stored_name)

    # ✅ save file
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # ✅ size check after save
    size_bytes = os.path.getsize(path)
    if size_bytes > MAX_MB * 1024 * 1024:
        try:
            os.remove(path)
        except Exception:
            pass
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_MB}MB)")

    job = {
        "upload_id": upload_id,
        "filename": safe_name,
        "stored_name": stored_name,
        "path": path,
        "ext": ext,
        "content_type": file.content_type,
        "size_bytes": size_bytes,
        "created_at": _utc_now_iso(),

        # ✅ مهم برشا: شكون ال index الهدف وين باش ندخلو logs
        "dataset": dataset,
        "source": source,
    }

    redis = request.app.state.redis
    await redis.lpush(QUEUE_KEY, json.dumps(job))

    return {
        "status": "queued",
        "upload_id": upload_id,
        "stored_name": stored_name,
        "queue": QUEUE_KEY,
        "size_bytes": size_bytes,
        "dataset": dataset,
        "source": source,
    }
