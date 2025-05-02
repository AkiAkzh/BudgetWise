import os
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # App config
    APP_NAME: str
    ENVIRONMENT: str
    DEBUG: bool
    HOST: str
    PORT: int

    # Auth config
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS : int
    JWT_SECRET_KEY: str
    JWT_REFRESH_SECRET_KEY:str
    JWT_ALGORITHM: str

    # DB config
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_HOST: str
    POSTGRES_PORT: str
    DATABASE_URL: str


    # SMTP
    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USER: str
    SMTP_PASSWORD: str


    # Хэширование
    PASSWORD_HASH_ALGORITHM: str = "bcrypt"

    class Config:
        env_file = os.path.join(os.path.dirname(__file__), '../../../environments/app.env')
        case_sensitive = True
        extra = "allow"

@lru_cache()
def get_settings():
    return Settings()
