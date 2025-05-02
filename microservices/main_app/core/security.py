import logging

from fastapi import Security, HTTPException, FastAPI
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError, ExpiredSignatureError
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.exc import NoResultFound
from uuid import UUID

from libs.exceptions import UnauthorizedError, NotFoundError, InternalServerError
from microservices.main_app.core.database import get_session
from microservices.main_app.api.auth.models.auth import Auth
from microservices.main_app.api.auth.schemas.auth_schema import GetMe
from microservices.main_app.core.config import get_settings
from sqlmodel import select
from fastapi import Depends

settings = get_settings()
security = HTTPBearer()

logger = logging.getLogger(__name__)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    session: AsyncSession = Depends(get_session)
) -> GetMe:
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp"]}
        )

        user_id = payload.get("sub")
        role = payload.get("role")

        if not user_id:
            logger.warning(f"No user id found in payload: {payload}")
            raise UnauthorizedError(detail="Invalid credentials: no user_id")

        statement = select(Auth).where(Auth.id == UUID(user_id))
        result = await session.exec(statement)
        user = result.first()

        if not user:
            logger.warning(f"User not found in DB: {user_id}")
            raise NotFoundError(detail="User not found")

        if not user.is_active:
            logger.warning(f"User not active: {user_id}")
            raise UnauthorizedError(detail="User is inactive")

        logger.info(f"User: {user_id}")
        return GetMe(user_id=user.id, role=user.role)

    except ExpiredSignatureError:
        logger.error(f"Expired token ")
        raise UnauthorizedError(detail="Token expired")
    except JWTError as e:
        logger.error(f"Invalid token: {str(e)}")
        raise UnauthorizedError(detail="Invalid token")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise InternalServerError(detail="Internal server error")
