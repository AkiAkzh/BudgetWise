import logging
from sqlalchemy.ext.asyncio import AsyncSession

from libs.exceptions import NotFoundError, UnauthorizedError
from microservices.main_app.api.auth.repository import auth_repository

logger = logging.getLogger(__name__)

async def verify_and_validate_refresh_token(user_id:str ,refresh_token : str , session : AsyncSession):
    logger.info(f"Founding refresh token for {user_id}")
    refresh_token_found = await auth_repository.get_user_by_refresh_token(refresh_token, session)

    if not refresh_token_found:
        logger.warning(f"Refresh token not found in DB")
        raise NotFoundError(detail="Refresh token not found in DB")

    if refresh_token_found.refresh_token != refresh_token:
        logger.warning(f"Refresh token mismatch for {user_id}")
        raise UnauthorizedError(detail="Refresh token mismatch")
    logger.info(f"Refresh token found for {user_id} and verified")