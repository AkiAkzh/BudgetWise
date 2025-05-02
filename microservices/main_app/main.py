from contextlib import asynccontextmanager

from fastapi import FastAPI

from libs.error_handler import ErrorHandlingMiddleware
from libs.logger import init_logger
from microservices.main_app.api.auth.api.auth_router import auth_router

from microservices.main_app.core.config import get_settings

from microservices.main_app.core.database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_logger()
    await init_db()
    yield

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    lifespan=lifespan,
)


app.add_middleware(ErrorHandlingMiddleware)

app.include_router(auth_router, prefix="/api/auth", tags=["auth"])

