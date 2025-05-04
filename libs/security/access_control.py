import logging
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from libs.exceptions import ConflictError, ForbiddenError, UnauthorizedError, NotFoundError
from microservices.main_app.api.auth.repository import auth_repository
from microservices.main_app.api.auth.schemas.auth_schema import GetMe

logger = logging.getLogger(__name__)

async def ensure_user_does_not_exist(user_email : str, session : AsyncSession) :
    if await auth_repository.get_user_by_email(user_email, session):
        logger.info(f"User {user_email} already registered")
        raise ConflictError(detail="User already exists")

async def get_active_user_by_email(user_email : str, session : AsyncSession) :
    user = await auth_repository.get_user_by_email(str(user_email), session)

    if not user:
        logger.warning(f"Auth login for {user_email} failed")
        raise UnauthorizedError(detail="Invalid email")

    if not user.is_active:
        logger.warning(f"User inactive for {user_email}")
        raise ForbiddenError(detail="User is inactive")

    return user

async def get_active_user_by_id(user_id : UUID, current_user: GetMe, session : AsyncSession) :
    user_found = await auth_repository.get_user_by_id(user_id=user_id, session=session)

    logger.info(f"User {user_id} found for {current_user.user_id}")
    if not user_found:
        logger.warning(f"User {user_id} not found for {current_user.user_id}")
        raise NotFoundError(detail="User not found")

    if not user_found.is_active:
        logger.warning(f"User inactive for {user_id}")
        raise ForbiddenError(detail="User is inactive")

    return user_found


def verify_user_by_id(user_id : UUID, current_user : GetMe):
    if current_user.role != "admin" and user_id != current_user.user_id:
        logger.warning(f"Access denied for {current_user.user_id}")
        raise ForbiddenError(detail="Access denied")