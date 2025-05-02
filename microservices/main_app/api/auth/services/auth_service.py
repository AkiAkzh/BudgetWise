import logging
from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from libs.utils import verify_user
from microservices.main_app.api.auth.repository.auth_repository import update_refresh_token
from microservices.main_app.api.auth.schemas.auth_schema import AuthLogin, AuthTokenResponse, GetMe, \
    RefreshTokenRequest, AuthChangePassword, AuthChangeRole, AuthRegister
from libs.exceptions import CustomHTTPException, InternalServerError, UnauthorizedError, NotFoundError, ForbiddenError, \
    BadRequestError, ConflictError

from microservices.main_app.api.auth.core.security import verify_password, create_access_token, create_refresh_token, \
    hash_password
from microservices.main_app.api.auth.repository import auth_repository


logger = logging.getLogger(__name__)


async def register(
        request: Request,
        register_data : AuthRegister,
        session: AsyncSession
):
    try:
        logger.info(f"Registering {register_data.email}")

        user_exists = await auth_repository.get_user_by_email(
            email=str(register_data.email),
            session=session,
        )
        if user_exists:
            logger.warning(f"User {register_data.email} already exists")
            raise ConflictError(detail="User already exists")

        hashed_password = hash_password(str(register_data.password))

        created_user = await auth_repository.create_user(
            email=str(register_data.email),
            hashed_password=hashed_password,
            session=session,
        )

        access_token = create_access_token({
            "user_id": str(created_user.id),
            "role": created_user.role,
        })
        refresh_token = create_refresh_token({
            "user_id": str(created_user.id),
            "role": created_user.role,
        })

        await auth_repository.update_refresh_token(
            user_id=created_user.id,
            new_refresh_token=refresh_token,
            session=session
        )

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

        user = await auth_repository.get_user_by_email(str(user_data.email), session)

        if not user:
            logger.warning(f"Auth login for {user_data.email} failed")
            raise UnauthorizedError(detail="Invalid email")

        if not user.is_active:
            logger.warning(f"User inactive for {user_data.email}")
            raise UnauthorizedError(detail="User is inactive")

        if not verify_password(user_data.password, user.hashed_password):
            raise UnauthorizedError(detail="Invalid password")

        access_token = create_access_token(data={"user_id": str(user.id), "role": user.role})
        refresh_token = create_refresh_token(data={"user_id": str(user.id), "role": user.role})

        await update_refresh_token(user_id=user.id, new_refresh_token=refresh_token, session=session)

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


async def logout(request: Request, session: AsyncSession, current_user: GetMe):
    try:
        logger.info(f"Logout for {current_user.user_id}")

        await auth_repository.update_refresh_token(
            user_id=current_user.user_id,
            new_refresh_token=None,
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

        logger.info(f"Founding refresh token for {current_user.user_id}")
        refresh_token_found = await auth_repository.get_user_by_refresh_token(refresh_token, session)

        if not refresh_token_found:
            logger.warning(f"Refresh token not found in DB")
            raise NotFoundError(detail="Refresh token not found in DB")

        if refresh_token_found.refresh_token != refresh_token:
            logger.warning(f"Refresh token mismatch for {current_user.user_id}")
            raise UnauthorizedError(detail="Refresh token mismatch")
        logger.info(f"Refresh token found for {current_user.user_id} and verified")

        new_access_token = create_access_token({
            "user_id": str(current_user.user_id),
            "role": current_user.role,
        })
        logger.info(f"New access token created for {current_user.user_id}")

        new_refresh_token = create_refresh_token({
            "user_id": str(current_user.user_id),
            "role": current_user.role,
        })
        logger.info(f"New refresh token created for {current_user.user_id}")

        await update_refresh_token(user_id=current_user.user_id, new_refresh_token=new_refresh_token, session=session)
        logger.info(f"New refresh token updated for {current_user.user_id}")

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



async def get_me(request:Request, current_user : GetMe):
    logger.info(f"Get me for {current_user.user_id}")
    return current_user


async def change_password_by_user_id(
        request:Request,
        password_request: AuthChangePassword ,
        user_id: UUID,
        current_user : GetMe,
        session: AsyncSession,
):
    try:
        logger.info(f"Change password for {current_user.user_id}")

        verify_user(user_id, current_user)

        user_found = await auth_repository.get_user_by_id(user_id=user_id, session=session)

        logger.info(f"User found for {current_user.user_id}")
        if not user_found:
            logger.warning(f"User not found for {current_user.user_id}")
            raise NotFoundError(detail="User not found")

        if not verify_password(password_request.old_password, user_found.hashed_password):
            logger.warning(f"Old password mismatch for {current_user.user_id}")
            raise BadRequestError(detail="Old password mismatch")

        new_password = hash_password(password_request.new_password)

        updated_user = await auth_repository.change_password_by_user_id(
            user_id,
            new_password=new_password,
            session=session)

        if updated_user is None:
            logger.warning(f"No changed password found for {current_user.user_id}")
            raise NotFoundError(detail="No changed password found")

        logger.info(f"Changed password for {current_user.user_id} successfully")
        return {"Message":"Password changed successfully"}

    except CustomHTTPException as http_exception:
        logger.error(f"Change password error for {current_user.user_id}", exc_info=True)
        raise http_exception
    except Exception as e:
        logger.error(f"Unexpected change password error for {current_user.user_id}", exc_info=True)
        raise InternalServerError(detail="Unexpected change password error")

async def change_role_by_user_id(
        request:Request,
        user_id : UUID,
        change_role_data : AuthChangeRole,
        current_user : GetMe,
        session: AsyncSession,
):
    try:
        logger.info(f"Change role for {current_user.user_id}")

        verify_user(user_id, current_user)

        user_found = await auth_repository.get_user_by_id(user_id=user_id, session=session)
        logger.info(f"User found for {current_user.user_id}")
        if not user_found:
            logger.warning(f"User not found for {current_user.user_id}")
            raise NotFoundError(detail="User not found")

        changed_user = await auth_repository.change_role_by_user_id(
            user_id=user_id,
            change_role_request=change_role_data,
            session=session
         )

    except CustomHTTPException as http_exception:
        raise http_exception
    except Exception as e:
        logger.error(f"")
        raise InternalServerError(detail="Unexpected error")