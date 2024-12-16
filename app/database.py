from sqlmodel import  create_engine, Session
from app.config import settings
import time
from sqlalchemy.exc import OperationalError

DATABASE_URL = (
    f"postgresql://{settings.postgres_user}:{settings.postgres_password}"
    f"@{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"
)

def get_db_engine():
    """
    创建数据库引擎，如果连接失败会重试最多5次
    Создает подключение к БД с 5 попытками переподключения при сбое
    """
    max_retries = 5
    retry_delay = 5 
    
    for attempt in range(max_retries):
        try:
            engine = create_engine(
                DATABASE_URL,
                echo=False,
                pool_pre_ping=True
            )

            with engine.connect():
                return engine
        except OperationalError as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(retry_delay)

engine = get_db_engine()

def get_session():
    """
    创建数据库会话的生成器函数，用于依赖注入
    Генератор сессий БД для внедрения зависимостей
    """
    with Session(engine) as session:
        yield session
