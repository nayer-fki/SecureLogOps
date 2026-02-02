from __future__ import annotations

import os
import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Literal, Tuple

import httpx
from fastapi import FastAPI, Header, HTTPException, Depends, Request, Response
from pydantic import BaseModel, Field, IPvAnyAddress, conint, constr, ConfigDict


# =========================================================
# Config
# =========================================================
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200").rstrip("/")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "ChangeMe_Elastic123!")
ES_INDEX = os.getenv("ES_INDEX", "logs-ingest-dev")  # Data stream alias/name

API_KEY = os.getenv("SEARCH_API_KEY", "ChangeMe_Search123!")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))

# Rate limit (V1 in-memory)
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))  # per minute per API key

# Fields whitelist (what the client can request in _source filtering)
ALLOWED_FIELDS = {
    "event.action",
    "event.outcome",
    "user.name",
    "source.ip",
    "source.port",
    "event.category",
    "@timestamp",
    "labels",
    "syslog.msg",
    "syslog.program",
}

ALLOWED_SORT_FIELDS = {"@timestamp"}
MAX_SIZE = 200

# Exclude known-bad docs (old pipeline tags)
EXCLUDE_BAD_TAGS = os.getenv("EXCLUDE_BAD_TAGS", "true").lower() in ("1", "true", "yes", "y")


# =========================================================
# Security
# =========================================================
def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> str:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid X-API-Key")
    return x_api_key


# =========================================================
# Simple in-memory rate limiter (V1)
# =========================================================
# key -> (window_epoch_minute, count)
_rate_state: Dict[str, Tuple[int, int]] = {}
_rate_lock = threading.Lock()


def rate_limit(_: Request, response: Response, api_key: str = Depends(require_api_key)) -> str:
    now = int(time.time())
    window = now // 60  # minute window

    with _rate_lock:
        win, cnt = _rate_state.get(api_key, (window, 0))
        if win != window:
            win, cnt = window, 0
        cnt += 1
        _rate_state[api_key] = (win, cnt)

    remaining = max(RATE_LIMIT_RPM - cnt, 0)
    reset_in = (window + 1) * 60 - now

    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_RPM)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(reset_in)

    if cnt > RATE_LIMIT_RPM:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    return api_key


# =========================================================
# Models
# =========================================================
class TimeRange(BaseModel):
    gte: Optional[str] = None
    lte: Optional[str] = None
    last_minutes: Optional[conint(ge=1, le=60 * 24 * 30)] = None  # max 30 days
    last_days: Optional[conint(ge=1, le=365)] = None  # max 365 days


class SearchFilters(BaseModel):
    time: Optional[TimeRange] = None

    event_action: Optional[constr(strip_whitespace=True, min_length=1, max_length=128)] = None
    event_outcome: Optional[Literal["success", "failure", "unknown"]] = None

    user_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=128)] = None
    source_ip: Optional[IPvAnyAddress] = None
    source_port: Optional[conint(ge=1, le=65535)] = None

    event_category: Optional[constr(strip_whitespace=True, min_length=1, max_length=64)] = None
    label: Optional[constr(strip_whitespace=True, min_length=1, max_length=64)] = None

    q: Optional[constr(strip_whitespace=True, min_length=1, max_length=200)] = None


class SearchRequest(BaseModel):
    filters: SearchFilters = Field(default_factory=SearchFilters)

    page: conint(ge=1, le=10000) = 1
    size: conint(ge=1, le=MAX_SIZE) = 25

    sort_field: Literal["@timestamp"] = "@timestamp"
    sort_order: Literal["asc", "desc"] = "desc"

    fields: Optional[List[str]] = None


class Hit(BaseModel):
    """
    Clean schema in responses:
      { index, id, score, source }
    while still reading Elasticsearch keys:
      _index/_id/_score/_source
    """
    model_config = ConfigDict(populate_by_name=True)

    index: str = Field(alias="_index")
    id: str = Field(alias="_id")
    score: Optional[float] = Field(default=None, alias="_score")
    source: Dict[str, Any] = Field(alias="_source")


class SearchResponse(BaseModel):
    took: int
    total: int
    hits: List[Hit]


class SummaryRequest(BaseModel):
    filters: SearchFilters = Field(default_factory=SearchFilters)
    top_n: conint(ge=1, le=50) = 10


class SummaryResponse(BaseModel):
    took: int
    total: int
    counts: Dict[str, int]  # {"success": x, "failure": y, "unknown": z}
    top_source_ip_failures: List[Dict[str, Any]]
    top_user_name_failures: List[Dict[str, Any]]


# =========================================================
# Helpers
# =========================================================
def _parse_iso(dt_str: str) -> datetime:
    if dt_str.endswith("Z"):
        dt_str = dt_str.replace("Z", "+00:00")
    return datetime.fromisoformat(dt_str)


def build_time_filter(tr: TimeRange) -> Optional[Dict[str, Any]]:
    now = datetime.now(timezone.utc)

    if tr.last_minutes:
        gte = now - timedelta(minutes=int(tr.last_minutes))
        return {"range": {"@timestamp": {"gte": gte.isoformat(), "lte": now.isoformat()}}}

    if tr.last_days:
        gte = now - timedelta(days=int(tr.last_days))
        return {"range": {"@timestamp": {"gte": gte.isoformat(), "lte": now.isoformat()}}}

    if tr.gte or tr.lte:
        rng: Dict[str, Any] = {}
        try:
            if tr.gte:
                rng["gte"] = _parse_iso(tr.gte).isoformat()
            if tr.lte:
                rng["lte"] = _parse_iso(tr.lte).isoformat()
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid time range format (ISO8601, ex: 2026-01-05T00:00:00Z)",
            )
        return {"range": {"@timestamp": rng}}

    return None


def _add_exclude_bad_docs(flt: List[Dict[str, Any]]) -> None:
    if not EXCLUDE_BAD_TAGS:
        return
    flt.append(
        {
            "bool": {
                "must_not": [
                    {"term": {"tags": "_rubyexception"}},
                    {"term": {"tags": "_dateparsefailure"}},
                ]
            }
        }
    )


def build_query(req: SearchRequest) -> Dict[str, Any]:
    f = req.filters
    must: List[Dict[str, Any]] = []
    flt: List[Dict[str, Any]] = []

    if f.time:
        tf = build_time_filter(f.time)
        if tf:
            flt.append(tf)

    _add_exclude_bad_docs(flt)

    # exact filters
    if f.event_action:
        flt.append({"term": {"event.action": f.event_action}})
    if f.event_outcome:
        flt.append({"term": {"event.outcome": f.event_outcome}})
    if f.user_name:
        flt.append({"term": {"user.name": f.user_name}})
    if f.source_ip:
        flt.append({"term": {"source.ip": str(f.source_ip)}})
    if f.source_port:
        flt.append({"term": {"source.port": int(f.source_port)}})

    if f.event_category:
        flt.append({"term": {"event.category": f.event_category}})
    if f.label:
        flt.append({"term": {"labels": f.label}})

    # safe text
    if f.q:
        must.append({"match": {"syslog.msg": {"query": f.q, "operator": "and"}}})

    from_ = (req.page - 1) * req.size

    # _source filtering whitelist
    src = None
    if req.fields is not None:
        bad = [x for x in req.fields if x not in ALLOWED_FIELDS]
        if bad:
            raise HTTPException(status_code=400, detail=f"fields contains non-allowed items: {bad}")
        src = req.fields

    if req.sort_field not in ALLOWED_SORT_FIELDS:
        raise HTTPException(status_code=400, detail="sort_field not allowed")

    body: Dict[str, Any] = {
        "track_total_hits": True,
        "from": from_,
        "size": req.size,
        "query": {"bool": {"filter": flt, "must": must}},
        "sort": [{req.sort_field: req.sort_order}],
    }
    if src is not None:
        body["_source"] = src

    return body


def build_summary_query(req: SummaryRequest) -> Dict[str, Any]:
    """
    V1 Pro+ summary (works with new + old docs):

    success if:
      - event.outcome=success OR event.action=ssh_login_success OR labels contains ssh_success
      - OR syslog.msg contains "Accepted password"

    failure if:
      - event.outcome=failure OR event.action=ssh_login_failed OR labels contains ssh_failed
      - OR syslog.msg contains "Failed password" / "Invalid user" / "authentication failure"

    unknown = everything else
    """
    f = req.filters
    flt: List[Dict[str, Any]] = []
    must: List[Dict[str, Any]] = []

    if f.time:
        tf = build_time_filter(f.time)
        if tf:
            flt.append(tf)

    _add_exclude_bad_docs(flt)

    # Optional narrowing filters (same as search)
    if f.event_action:
        flt.append({"term": {"event.action": f.event_action}})
    if f.event_outcome:
        flt.append({"term": {"event.outcome": f.event_outcome}})
    if f.user_name:
        flt.append({"term": {"user.name": f.user_name}})
    if f.source_ip:
        flt.append({"term": {"source.ip": str(f.source_ip)}})
    if f.source_port:
        flt.append({"term": {"source.port": int(f.source_port)}})
    if f.event_category:
        flt.append({"term": {"event.category": f.event_category}})
    if f.label:
        flt.append({"term": {"labels": f.label}})

    if f.q:
        must.append({"match": {"syslog.msg": {"query": f.q, "operator": "and"}}})

    topn = int(req.top_n)

    # ✅ Success classification (structured + fallback text)
    success_should = [
        {"term": {"event.outcome": "success"}},
        {"term": {"event.action": "ssh_login_success"}},
        {"term": {"labels": "ssh_success"}},
        {"match_phrase": {"syslog.msg": "Accepted password"}},
    ]

    # ✅ Failure classification (structured + fallback text)
    failure_should = [
        {"term": {"event.outcome": "failure"}},
        {"term": {"event.action": "ssh_login_failed"}},
        {"term": {"labels": "ssh_failed"}},
        {"match_phrase": {"syslog.msg": "Failed password"}},
        {"match_phrase": {"syslog.msg": "Invalid user"}},
        {"match_phrase": {"syslog.msg": "authentication failure"}},
    ]

    body: Dict[str, Any] = {
        "track_total_hits": True,
        "size": 0,
        "query": {"bool": {"filter": flt, "must": must}},
        "aggs": {
            "success": {
                "filter": {"bool": {"should": success_should, "minimum_should_match": 1}}
            },
            "failure": {
                "filter": {"bool": {"should": failure_should, "minimum_should_match": 1}},
                "aggs": {
                    "top_source_ip": {"terms": {"field": "source.ip", "size": topn}},
                    "top_user_name": {"terms": {"field": "user.name", "size": topn}},
                },
            },
            "unknown": {
                "filter": {
                    "bool": {
                        "must_not": [
                            {"bool": {"should": success_should, "minimum_should_match": 1}},
                            {"bool": {"should": failure_should, "minimum_should_match": 1}},
                        ]
                    }
                }
            },
        },
    }
    return body


async def es_post(path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{ES_URL}/{path.lstrip('/')}"
    auth = (ES_USER, ES_PASS)

    # Better default pooling for multiple requests
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    timeout = httpx.Timeout(REQUEST_TIMEOUT, connect=min(5.0, REQUEST_TIMEOUT))

    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        r = await client.post(url, json=body, auth=auth)
        if r.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"Elasticsearch error {r.status_code}: {r.text[:500]}")
        return r.json()


async def es_search(query_body: Dict[str, Any]) -> Dict[str, Any]:
    return await es_post(f"{ES_INDEX}/_search", query_body)


# =========================================================
# App
# =========================================================
app = FastAPI(title="SecureLogOps Search Service", version="1.1.2")


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "search-service", "es_index": ES_INDEX}


@app.get("/fields")
async def fields(_: str = Depends(require_api_key)) -> Dict[str, Any]:
    return {
        "allowed_fields": sorted(list(ALLOWED_FIELDS)),
        "allowed_sort_fields": sorted(list(ALLOWED_SORT_FIELDS)),
        "max_size": MAX_SIZE,
        "exclude_bad_docs": EXCLUDE_BAD_TAGS,
        "rate_limit_rpm": RATE_LIMIT_RPM,
    }


@app.get("/debug/es")
async def debug_es(_: str = Depends(require_api_key)) -> Dict[str, Any]:
    """
    Quick ES connectivity check (useful in Docker networking issues).
    """
    try:
        url = f"{ES_URL}/_cluster/health"
        timeout = httpx.Timeout(min(5.0, REQUEST_TIMEOUT), connect=min(3.0, REQUEST_TIMEOUT))
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, auth=(ES_USER, ES_PASS))
            ctype = (r.headers.get("content-type") or "").lower()
            body = r.json() if ctype.startswith("application/json") else (r.text[:200] if r.text else "")
            return {"ok": r.status_code < 400, "status_code": r.status_code, "body": body}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/search", response_model=SearchResponse)
async def search(
    req: SearchRequest,
    response: Response,
    _: str = Depends(rate_limit),
) -> SearchResponse:
    body = build_query(req)
    data = await es_search(body)

    total = int(data.get("hits", {}).get("total", {}).get("value", 0))
    hits_raw = data.get("hits", {}).get("hits", [])

    hits = [Hit.model_validate(h) for h in hits_raw]

    return SearchResponse(
        took=int(data.get("took", 0)),
        total=total,
        hits=hits,
    )


@app.post("/search/summary", response_model=SummaryResponse)
async def search_summary(
    req: SummaryRequest,
    response: Response,
    _: str = Depends(rate_limit),
) -> SummaryResponse:
    body = build_summary_query(req)
    data = await es_search(body)

    total = int(data.get("hits", {}).get("total", {}).get("value", 0))
    took = int(data.get("took", 0))

    aggs = data.get("aggregations", {}) or {}

    success_count = int((aggs.get("success") or {}).get("doc_count", 0))
    failure_obj = aggs.get("failure") or {}
    failure_count = int(failure_obj.get("doc_count", 0))
    unknown_count = int((aggs.get("unknown") or {}).get("doc_count", 0))

    counts: Dict[str, int] = {
        "success": success_count,
        "failure": failure_count,
        "unknown": unknown_count,
    }

    top_ip = (failure_obj.get("top_source_ip") or {}).get("buckets", []) or []
    top_user = (failure_obj.get("top_user_name") or {}).get("buckets", []) or []

    top_source_ip_failures = [{"key": x.get("key"), "count": int(x.get("doc_count", 0))} for x in top_ip]
    top_user_name_failures = [{"key": x.get("key"), "count": int(x.get("doc_count", 0))} for x in top_user]

    return SummaryResponse(
        took=took,
        total=total,
        counts=counts,
        top_source_ip_failures=top_source_ip_failures,
        top_user_name_failures=top_user_name_failures,
    )
