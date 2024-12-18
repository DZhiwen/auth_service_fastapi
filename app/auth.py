from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from redis import Redis
from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
redis_client = Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)

def create_access_token(data: Dict[str, Any]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "token_type": "access"})
    return jwt.encode(to_encode, settings.secret_key, algorithm="HS256")

def create_refresh_token(data: Dict[str, Any]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "token_type": "refresh"})
    return jwt.encode(to_encode, settings.secret_key, algorithm="HS256")

def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError:
        return None

def invalidate_access_token(token: str) -> None:

    redis_client.set(f"access_token:{token}", "invalid")

def is_access_token_invalid(token: str) -> bool:

    return bool(redis_client.get(f"access_token:{token}"))

def verify_token_type(token: str, expected_type: str) -> bool:
    payload = decode_token(token)
    if not payload:
        return False
    return payload.get("token_type") == expected_type
