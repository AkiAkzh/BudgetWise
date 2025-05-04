import logging

from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from microservices.main_app.api.auth.repository import auth_repository


logger = logging.getLogger(__name__)

async def store_refresh_token(user_id: UUID, refresh_token: str | None, session: AsyncSession):
    await auth_repository.update_refresh_token(user_id, refresh_token, session)
    logger.info(f"New refresh token updated for {user_id}")
