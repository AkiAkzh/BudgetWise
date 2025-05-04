import logging
from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from libs.security.access_control import verify_user_by_id, get_active_user_by_id
from libs.security.password_validation import ensure_password_matches
from microservices.main_app.api.auth.schemas.auth_schema import GetMe, AuthChangePassword, AuthChangeRole
from libs.exceptions import CustomHTTPException, InternalServerError, NotFoundError, \
    BadRequestError, ConflictError

from microservices.main_app.api.auth.core.security import verify_password, hash_password
from microservices.main_app.api.auth.repository import auth_repository


logger = logging.getLogger(__name__)


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

        verify_user_by_id(
            user_id=user_id,
            current_user=current_user
        )

        user_found = await get_active_user_by_id(
            user_id=user_id,
            current_user=current_user,
            session=session
        )

        ensure_password_matches(
            old_password=password_request.old_password,
            hashed_password=user_found.hashed_password
        )

        new_password = hash_password(password_request.new_password)

        updated_user = await auth_repository.update_password_by_user_id(
            user_id=user_id,
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
        logger.info(f"Request to change role for user {user_id} by {current_user.user_id}")


        verify_user_by_id(user_id, current_user)

        user_found = await get_active_user_by_id(
            user_id=user_id,
            current_user=current_user,
            session=session
        )
        if user_found.role == change_role_data.new_role:
            logger.warning(f"User {user_id} already has role '{change_role_data.new_role}'. No change needed.")
            raise ConflictError(detail=f"User already has role '{change_role_data.new_role}'")

        changed_user = await auth_repository.update_role_by_user_id(
            user_id=user_id,
            change_role_request=change_role_data,
            session=session
        )

        if changed_user is None:
            logger.warning(f"Role change failed: user {user_id} not found")
            raise NotFoundError(detail="User not found for role change")

        logger.info(f"User {user_id}'s role successfully changed to '{change_role_data.new_role}' by {current_user.user_id}")
        return {"message": f"User role changed to '{change_role_data.new_role}'"}
    except CustomHTTPException as http_exception:
        raise http_exception
    except Exception as e:
        logger.error(f"Unexpected role change error for {current_user.user_id}: {str(e)}", exc_info=True)
        raise InternalServerError(detail="Unexpected error")