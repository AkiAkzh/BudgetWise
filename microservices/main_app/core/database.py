from sqlalchemy.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import sessionmaker
from microservices.main_app.core.base import Base

from microservices.main_app.core.config import get_settings

settings = get_settings()

engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,  # вывод SQL-запросов
)


async_session_factory = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Функция для зависимости FastAPI
async def get_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session

async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
