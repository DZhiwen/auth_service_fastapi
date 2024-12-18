from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlmodel import Session
from app.models import (
    UserRegister,
    TokenRequest,
    MessageResponse,
    LoginResponse,
    RefreshTokenResponse,
    UserResponse,
    RegisterResponse,
    LoginRequest
)
from app.database import get_session
from app.dependencies import security
from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    invalidate_access_token,
    verify_token_type
)
from app.crud import get_user_by_email, create_user, log_login


router = APIRouter(tags=['Auth'])

@router.post("/register", response_model=RegisterResponse)
def register(user: UserRegister, session: Session = Depends(get_session)):
    """
    Создание нового пользователя в системе, если email еще не зарегистрирован.
    """
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


@router.post("/login", response_model=LoginResponse)
def login(
    request: Request,
    login_data: LoginRequest,
    session: Session = Depends(get_session)
):
    """
    Вход в систему по email и паролю, возвращает access и refresh токены.
    """
    db_user = get_user_by_email(session, login_data.email)
    
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not registered"
        )
    
    if not verify_password(login_data.password, db_user.hashed_password):
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
def refresh(
    token_data: TokenRequest,
    auth: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Обновление access токена с использованием refresh токена.
    """
    # 验证 refresh token 类型 Проверка типа токена обновления
    if not verify_token_type(token_data.refresh_token, "refresh"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Refresh token required."
        )

    # 验证 refresh token Проверка токена обновления
    refresh_payload = decode_token(token_data.refresh_token)
    if not refresh_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token format"
        )
    
    # 获取当前的 access token 并使其失效 Получение текущего токена доступа и его инвалидация
    current_access_token = auth.credentials
    invalidate_access_token(current_access_token)
    
    # 创建新的 access token Создание нового токена доступа
    access_token = create_access_token({"sub": refresh_payload["sub"]})
    
    return RefreshTokenResponse(
        access_token=access_token
    )

@router.post("/logout", response_model=MessageResponse)
def logout(auth: HTTPAuthorizationCredentials = Depends(security)):
    """
    登出，使当前的 access token 失效
    Удаляет токен пользователя из списка действительных.
    """
    # 验证是否为 access token  Проверка, является ли токен токеном доступа
    token = auth.credentials
    if not verify_token_type(token, "access"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Access token required."
        )

    # 使 access token 失效  Инвалидация токена доступа
    invalidate_access_token(token)
    
    return MessageResponse(
        message="Logged out successfully"
    )
