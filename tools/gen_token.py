import os, time
import jwt  # pyjwt
from datetime import datetime, timedelta, timezone

SECRET = os.getenv("JWT_SECRET", "ChangeMe_JWT_Secret123!")

def gen(sub: str, role: str, days: int = 7):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=days)).timestamp()),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

if __name__ == "__main__":
    for sub, role in [("admin1","admin"),("analyst1","analyst"),("viewer1","viewer")]:
        print(role.upper(), "=", gen(sub, role, days=7))
