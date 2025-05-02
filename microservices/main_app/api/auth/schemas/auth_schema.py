from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class AuthBase(BaseModel):
    email: EmailStr = Field(...)
    role : str = Field(default="User")
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)

class AuthInDB(AuthBase):
    id: UUID
    hashed_password: str
    refresh_token: Optional[str]
    created_at: datetime = Field(default_factory=lambda : datetime.utcnow().isoformat())
    updated_at: datetime = Field(default_factory=lambda : datetime.utcnow().isoformat())


class AuthLogin(BaseModel):
    email: EmailStr = Field(...)
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "email": "JonhDoe@gmail.com",
                "password": "StrongP@ssw0rd!",
            }
        }


class AuthRegister(BaseModel):
    email: EmailStr = Field(...)
    password : str = Field(...)

    class Config:
        json_schema_extra = {
            "example": {
                "email": "JonhDoe@gmail.com",
                "password": "StrongP@ssw0rd!",
            }
        }
class GetMe(BaseModel):
    user_id: UUID
    role: str

class AuthTokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str]
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AuthChangeRole(BaseModel):
    new_role: str


class AuthChangePassword(BaseModel):
    old_password: str
    new_password: str


class AuthLogoutRequest(BaseModel):
    refresh_token: str
