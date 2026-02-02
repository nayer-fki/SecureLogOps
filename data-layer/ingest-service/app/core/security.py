from fastapi import Header, HTTPException
from app.core.config import API_KEY

def require_api_key(x_api_key: str = Header(default=None, alias="X-API-Key")):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized (invalid API key)")
    return True
