from pydantic import BaseSettings

class Settings(BaseSettings):
    postgres_user: str
    postgres_password: str
    postgres_db: str
    postgres_host: str
    postgres_port: int
    secret_key: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    redis_host: str
    redis_port: int

    class Config:
        env_file = ".env"

settings = Settings()