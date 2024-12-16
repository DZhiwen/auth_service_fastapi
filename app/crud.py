from sqlmodel import Session, select
from app.models import User, LoginHistory
from typing import List

from datetime import datetime, timezone
from pydantic import EmailStr
from sqlmodel import SQLModel, Field, Session, select
from typing import Optional  



def get_user_by_email(session: Session, email: EmailStr) -> Optional[User]:
    return session.exec(select(User).where(User.email == email)).first()

def create_user(session: Session, email: EmailStr, hashed_password: str) -> User:
    user = User(email=email, hashed_password=hashed_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def update_user(session: Session, user: User, email: Optional[EmailStr] = None, hashed_password: Optional[str] = None) -> User:
    if email:
        user.email = email
    if hashed_password:
        user.hashed_password = hashed_password
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def log_login(session: Session, user_id: int, user_agent: str):
    history = LoginHistory(user_id=user_id, user_agent=user_agent)
    session.add(history)
    session.commit()

def get_login_history(session: Session, user_id: int) -> List[LoginHistory]:
    """
    获取用户的登录历史记录，按时间降序排列
    Получает историю входов пользователя, отсортированную по времени по убыванию
    """
    return session.exec(
        select(LoginHistory)
        .where(LoginHistory.user_id == user_id)
        .order_by(LoginHistory.login_time.desc())
    ).all()
