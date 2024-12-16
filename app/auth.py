from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from redis import Redis
from app.config import settings

pwd_context: CryptContext = CryptContext(schemes=["bcrypt"], deprecated="auto")
redis_client: Redis = Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(data: Dict[str, Any]) -> str:
    expire: datetime = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    data.update({"exp": expire})
    return jwt.encode(data, settings.secret_key, algorithm="HS256")


def create_refresh_token(data: Dict[str, Any]) -> str:
    expire: datetime = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    data.update({"exp": expire})
    return jwt.encode(data, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError:
        return None


def invalidate_token(token: str) -> None:
    redis_client.set(token, "invalid", ex=settings.refresh_token_expire_days * 24 * 3600)


def is_token_invalid(token: str) -> bool:
    return redis_client.exists(token) == 1
