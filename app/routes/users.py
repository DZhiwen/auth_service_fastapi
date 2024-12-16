from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from app.models import User
from app.database import get_session
from app.dependencies import get_current_user
from app.crud import (
    get_user_by_email,
    update_user,
    get_login_history,
)
from pydantic import BaseModel
from app.auth import hash_password
router = APIRouter(prefix="/users", tags=["Users"])
from pydantic import EmailStr

class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = None

@router.put("/update")
def update_user_info(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    if user_update.email and user_update.email != current_user.email:
        if get_user_by_email(session, user_update.email):
            raise HTTPException(status_code=400, detail="Email already exists")
    
    hashed_password = None
    if user_update.password:
        hashed_password = hash_password(user_update.password)
    
    update_user(
        session,
        current_user,
        email=user_update.email,
        hashed_password=hashed_password
    )
    
    return {"message": "User updated successfully"}

@router.get("/history")
def get_user_login_history(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    history = get_login_history(session, current_user.id)
    return [{
        "user_agent": h.user_agent,
        "login_time": h.login_time.isoformat()
    } for h in history]
