from datetime import datetime
from typing import Optional, Dict, Any, List
import hashlib

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ReturnDocument

from .db import incidents_col


class InvalidObjectId(ValueError):
    """Raised when a provided id is not a valid MongoDB ObjectId."""


def _oid(id_: str) -> ObjectId:
    try:
        return ObjectId(id_)
    except (InvalidId, TypeError):
        raise InvalidObjectId("Invalid incident id")


def _ensure_title(doc: Dict[str, Any]) -> None:
    """
    ✅ Fix for ResponseValidationError:
    Some older incidents in Mongo may not have 'title'.
    We generate a fallback title so response_model validation never crashes.
    """
    if doc.get("title"):
        return

    type_ = doc.get("type", "incident")
    sev = doc.get("severity", "medium")

    src = doc.get("source") or {}
    ip = src.get("ip") or doc.get("source_ip") or "n/a"

    doc["title"] = f"{type_.upper()} ({sev}) from {ip}"


def _to_out(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not doc:
        return None

    doc = dict(doc)  # avoid mutating motor internal dict

    # id mapping
    doc["id"] = str(doc["_id"])
    del doc["_id"]

    # ✅ normalize required fields for response_model
    _ensure_title(doc)

    # make sure nested defaults exist (avoid None issues)
    if "source" not in doc or doc["source"] is None:
        doc["source"] = {}

    if "tags" not in doc or doc["tags"] is None:
        doc["tags"] = []

    if "evidence" not in doc or doc["evidence"] is None:
        doc["evidence"] = {"logs": [], "wazuh": {}, "metrics": {}}

    return doc


async def list_incidents(
    status: Optional[str],
    severity: Optional[str],
    limit: int,
    skip: int,
) -> List[Dict[str, Any]]:
    q: Dict[str, Any] = {}
    if status:
        q["status"] = status
    if severity:
        q["severity"] = severity

    cur = (
        incidents_col()
        .find(q)
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )
    docs = await cur.to_list(length=limit)
    return [_to_out(d) for d in docs if d]


async def get_incident(id_: str) -> Optional[Dict[str, Any]]:
    doc = await incidents_col().find_one({"_id": _oid(id_)})
    return _to_out(doc)


async def ack_incident(id_: str, user: str) -> Optional[Dict[str, Any]]:
    now = datetime.utcnow()
    res = await incidents_col().find_one_and_update(
        {"_id": _oid(id_), "status": {"$in": ["open", "ack"]}},
        {"$set": {"status": "ack", "acked_at": now, "acked_by": user, "updated_at": now}},
        return_document=ReturnDocument.AFTER,
    )
    return _to_out(res)


async def close_incident(id_: str, user: str) -> Optional[Dict[str, Any]]:
    now = datetime.utcnow()
    res = await incidents_col().find_one_and_update(
        {"_id": _oid(id_), "status": {"$in": ["open", "ack", "closed"]}},
        {"$set": {"status": "closed", "closed_at": now, "closed_by": user, "updated_at": now}},
        return_document=ReturnDocument.AFTER,
    )
    return _to_out(res)


async def overview_stats() -> Dict[str, Any]:
    col = incidents_col()

    pipeline = [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]
    status_counts = {d["_id"]: d["count"] for d in await col.aggregate(pipeline).to_list(None)}

    sev_pipe = [
        {"$match": {"status": {"$ne": "closed"}}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    sev_counts = {d["_id"]: d["count"] for d in await col.aggregate(sev_pipe).to_list(None)}

    return {
        "status": {
            "open": status_counts.get("open", 0),
            "ack": status_counts.get("ack", 0),
            "closed": status_counts.get("closed", 0),
        },
        "open_by_severity": {
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
        },
    }


# ------------------ internal upsert helpers ------------------

def compute_fingerprint(type_: str, source_ip: Optional[str], title: str) -> str:
    base = f"{type_}|{source_ip or 'none'}|{title}".lower().strip()
    return hashlib.sha1(base.encode("utf-8")).hexdigest()


async def upsert_incident(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Upsert by fingerprint:
    - If an incident with same fingerprint exists and status != closed -> update it (evidence + updated_at)
    - If it does not exist -> create new incident (status=open)
    - If the only match is closed -> create a new incident instance with fingerprint suffix (timestamp)
    """
    now = datetime.utcnow()

    src = payload.get("source") or {}

    # ✅ if title missing from payload, generate it (extra safety)
    if not payload.get("title"):
        type_ = payload.get("type", "incident")
        sev = payload.get("severity", "medium")
        ip = src.get("ip") or "n/a"
        payload["title"] = f"{type_.upper()} ({sev}) from {ip}"

    fp = payload.get("fingerprint") or compute_fingerprint(
        payload["type"], src.get("ip"), payload["title"]
    )

    update = {
        "$set": {
            "severity": payload["severity"],
            "title": payload["title"],
            "description": payload.get("description"),
            "source": src,
            "tags": payload.get("tags", []),
            "evidence": payload.get("evidence", {}),
            "updated_at": now,
        },
        "$setOnInsert": {
            "fingerprint": fp,
            "status": "open",
            "type": payload["type"],
            "created_at": now,
            "acked_at": None,
            "acked_by": None,
            "closed_at": None,
            "closed_by": None,
        },
    }

    # Update existing (if not closed) OR create new
    res = await incidents_col().find_one_and_update(
        {"fingerprint": fp, "status": {"$ne": "closed"}},
        update,
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )

    # If existing is closed only => create a new instance
    if not res:
        fp2 = f"{fp}-{now.strftime('%Y%m%d%H%M%S')}"
        update["$setOnInsert"]["fingerprint"] = fp2
        res = await incidents_col().find_one_and_update(
            {"fingerprint": fp2},
            update,
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

    return _to_out(res)
