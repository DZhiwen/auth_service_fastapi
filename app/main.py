from fastapi import FastAPI
from app.models import SQLModel
from app.database import engine
from app.routes import auth, users

app = FastAPI(
    title="Python Auth Service",
    description="Auth service that provides authentication and authorization of users using JWT tokens.\
    \nImplement the functionality of storing data in the database and processing requests taking into account secure token management.",
    version="1.0.0"
)


# 包含路由
app.include_router(auth.router)
app.include_router(users.router)
