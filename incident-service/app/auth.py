from typing import Optional, Literal, Dict, Any

import jwt
from fastapi import Header, HTTPException, status, Depends
from pydantic import BaseModel

from .config import settings

Role = Literal["admin", "analyst", "viewer"]

class UserCtx(BaseModel):
    username: str
    role: Role

def _unauthorized(msg="Unauthorized"):
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

def _forbidden(msg="Forbidden"):
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)

def get_current_user(authorization: Optional[str] = Header(default=None)) -> UserCtx:
    """
    Authorization: Bearer <JWT>
    payload must contain:
      - sub (or username)
      - role: admin|analyst|viewer
    """
    if not settings.AUTH_ENABLED:
        return UserCtx(username="dev", role="admin")

    if not authorization or not authorization.lower().startswith("bearer "):
        _unauthorized("Missing Bearer token")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload: Dict[str, Any] = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        _unauthorized("Token expired")
    except jwt.InvalidTokenError:
        _unauthorized("Invalid token")

    username = payload.get("sub") or payload.get("username")
    role = payload.get("role")

    if not username or role not in ("admin", "analyst", "viewer"):
        _unauthorized("Invalid token claims")

    return UserCtx(username=str(username), role=role)

def require_roles(*allowed: Role):
    def _dep(user: UserCtx = Depends(get_current_user)) -> UserCtx:
        if user.role not in allowed:
            _forbidden("Insufficient role")
        return user
    return _dep
