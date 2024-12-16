from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from sqlmodel import Session
from app.models import (
    UserRegister,
    UserLogin,
    TokenRequest,
    MessageResponse,
    LoginResponse,
    RefreshTokenResponse,
    UserResponse,
    RegisterResponse
)
from app.database import get_session
from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    invalidate_token,
    is_token_invalid,
)
from app.crud import get_user_by_email, create_user, log_login
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter(tags=['Auth'])


@router.post("/register", response_model=RegisterResponse, summary="your email is your username")
def register(user: UserRegister, session: Session = Depends(get_session)):
    if get_user_by_email(session, user.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    hashed_password = hash_password(user.password)
    db_user = create_user(session, user.email, hashed_password)
    
    return RegisterResponse(
        message="User registered successfully",
        user=UserResponse(
            id=db_user.id,
            email=db_user.email,
            created_at=db_user.created_at
        )
    )




@router.post("/login", response_model=LoginResponse, summary="username = your email")
def login(
    request: Request,
    session: Session = Depends(get_session),
    form_data: OAuth2PasswordRequestForm = Depends() 
):
    db_user = get_user_by_email(session, form_data.username)
    
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not registered"
        )
    
    if not verify_password(form_data.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )
    
    log_login(session, db_user.id, request.headers.get("user-agent", "unknown"))
    
    access_token = create_access_token({"sub": db_user.email})
    refresh_token = create_refresh_token({"sub": db_user.email})
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=db_user.id,
        email=db_user.email
    )


@router.post("/refresh", response_model=RefreshTokenResponse)
def refresh(token_data: TokenRequest):
    payload = decode_token(token_data.refresh_token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token format"
        )
    
    if is_token_invalid(token_data.refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been invalidated"
        )
    
    access_token = create_access_token({"sub": payload["sub"]})
    
    return RefreshTokenResponse(
        access_token=access_token
    )

@router.post("/logout", response_model=MessageResponse)
def logout(token_data: TokenRequest):
    invalidate_token(token_data.refresh_token)
    return MessageResponse(
        message="Logged out successfully"
    )