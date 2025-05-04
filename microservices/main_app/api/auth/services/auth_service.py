import logging
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from libs.security.access_control import ensure_user_does_not_exist, get_active_user_by_email
from libs.security.token_validators import verify_and_validate_refresh_token
from microservices.main_app.api.auth.helpers.token_pair import create_token_pair
from microservices.main_app.api.auth.helpers.token_updater import store_refresh_token
from microservices.main_app.api.auth.schemas.auth_schema import AuthLogin, AuthTokenResponse, GetMe, \
    RefreshTokenRequest, AuthRegister
from libs.exceptions import CustomHTTPException, InternalServerError, UnauthorizedError, BadRequestError
from microservices.main_app.api.auth.core.security import verify_password ,hash_password
from microservices.main_app.api.auth.repository import auth_repository


logger = logging.getLogger(__name__)


async def register(
        request: Request,
        register_data : AuthRegister,
        session: AsyncSession
):
    try:
        logger.info(f"Registering {register_data.email}")

        await ensure_user_does_not_exist(str(register_data.email), session)

        hashed_password = hash_password(register_data.password)

        created_user = await auth_repository.create_user(
            email=str(register_data.email),
            hashed_password=hashed_password,
            session=session,
        )

        access_token, refresh_token = create_token_pair(str(created_user.id), created_user.role)

        await store_refresh_token(created_user.id, refresh_token, session)

        logger.info(f"User {created_user.email} registered successfully")

        return AuthTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )

    except CustomHTTPException as http_exception:
        logger.error(f"Error registering {http_exception}", exc_info=True)
        raise http_exception
    except Exception as exception:
        logger.error(f"Error registering {exception}", exc_info=True)
        raise InternalServerError(detail=f"Error registering {exception}")



async def auth_login(
    request: Request,
    user_data: AuthLogin,
    session: AsyncSession
) -> AuthTokenResponse:
    try:
        logger.info(f"Auth login for {user_data.email}")

        user = await get_active_user_by_email( str(user_data.email), session)

        if not verify_password(user_data.password, user.hashed_password):
            raise BadRequestError(detail="Invalid password")

        access_token, refresh_token = create_token_pair(str(user.id), user.role)

        await store_refresh_token(user.id, refresh_token, session)

        return AuthTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )

    except CustomHTTPException as err:
        logger.error(f"Login error for {user_data.email}", exc_info=True)
        raise err
    except Exception as e:
        logger.error(f"Unexpected login error for {user_data.email}: {str(e)}", exc_info=True)
        raise InternalServerError(detail="Unexpected login error")


async def logout(request: Request, current_user: GetMe, session: AsyncSession):
    try:
        logger.info(f"Logout for {current_user.user_id}")

        await store_refresh_token(
            user_id=current_user.user_id,
            refresh_token=None,
            session=session
        )

        logger.info(f"Refresh token removed for {current_user.user_id}")
        return {"message": "Successfully logged out"}
    except CustomHTTPException as http_exception:
        logger.error(f"Logout error for {current_user.user_id}", exc_info=True)
        raise http_exception
    except Exception as e:
        logger.error(f"Unexpected logout error for {current_user.user_id}", exc_info=True)
        raise InternalServerError(detail="Unexpected logout error")

async def refresh_access_token(request: Request,refresh_token: RefreshTokenRequest, session: AsyncSession, current_user: GetMe):
    try:
        data = refresh_token
        logger.info(f"Refresh token for {current_user.user_id}")
        if data.refresh_token is None:
            logger.warning(f"Refresh token is missing for {current_user.user_id}")
            raise UnauthorizedError(detail="refresh token is missing")

        refresh_token = data.refresh_token

        await verify_and_validate_refresh_token(
            user_id=str(current_user.user_id),
            refresh_token=refresh_token,
            session=session
        )

        new_access_token, new_refresh_token = create_token_pair(
            str(current_user.user_id),
            current_user.role
        )

        await store_refresh_token(
            user_id=current_user.user_id,
            refresh_token=new_refresh_token,
            session=session
        )

        logger.info(f"Token refreshed for {current_user.user_id} successfully")
        return AuthTokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token
        )
    except CustomHTTPException as http_exception:
        logger.error(f"Refresh error for {current_user.user_id}", exc_info=True)
        raise http_exception
    except Exception as e:
        logger.error(f"Unexpected refresh error for {current_user.user_id}", exc_info=True)
        raise InternalServerError(detail="Unexpected refresh error")


