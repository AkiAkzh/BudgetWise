from http.client import responses
from uuid import UUID

from fastapi import APIRouter, Request, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from libs.common_models import SuccessResponse
from libs.docs.docs import DEFAULT_RESPONSES
from microservices.main_app.api.auth.schemas.auth_schema import AuthLogin, AuthTokenResponse, GetMe, \
    RefreshTokenRequest, AuthChangePassword, AuthChangeRole, AuthRegister
from microservices.main_app.api.auth.services import auth_service
from microservices.main_app.core.database import get_session
from microservices.main_app.core.security import get_current_user
from microservices.main_app.api.auth.services import profile_service

auth_router = APIRouter()

@auth_router.post(
    "/register",
    status_code=201,
    response_model=SuccessResponse[AuthTokenResponse],
    responses={**DEFAULT_RESPONSES }
)
async def register_auth(
        request: Request,
        register_data: AuthRegister,
        session: AsyncSession = Depends(get_session)
):
    """
        Register a new user.

        - **email**: User's email address
        - **password**: User's password

        Returns:
            Access and refresh tokens if registration is successful.
    """

    result = await auth_service.register(
        request=request,
        register_data=register_data,
        session=session,
    )
    return SuccessResponse(
        data=result,
        message=f"Registered successfully!",
    )


@auth_router.post(
    "/login",
    response_model=SuccessResponse[AuthTokenResponse],
    responses={**DEFAULT_RESPONSES }
)
async def login(request: Request, login_data : AuthLogin,
    session: AsyncSession = Depends(get_session)):
    """
        Log in a user.

        - **email**: User's email
        - **password**: User's password

        Returns:
            Access and refresh tokens if login is successful.
    """

    result = await auth_service.auth_login(request=request, user_data=login_data, session=session)

    return SuccessResponse(data=result, message="Successfully logged in")
@auth_router.post(
    "/logout",
    status_code=204,
    responses={**DEFAULT_RESPONSES })
async def logout(
        request: Request,
        session: AsyncSession = Depends(get_session),
        user : GetMe = Depends(get_current_user)
):
    """
        Log out the currently authenticated user.

        Removes the refresh token from the database.
    """

    await auth_service.logout(request=request, session=session, current_user=user)
    return Response(status_code=204)

@auth_router.post(
    "/refresh",
    status_code=200,
    response_model=SuccessResponse[AuthTokenResponse],
    responses={**DEFAULT_RESPONSES }
)
async def refresh(
        request : Request,
        refresh_token : RefreshTokenRequest,
        user : GetMe = Depends(get_current_user),
        session: AsyncSession = Depends(get_session)
):
    """
        Refresh the access token using a valid refresh token.

        Returns:
            A new access and refresh token pair.
    """

    result = await auth_service.refresh_access_token(request=request, refresh_token=refresh_token, session=session, current_user=user)
    return SuccessResponse(data=result, message="Successfully refreshed")

@auth_router.get(
    "/me",
    status_code=200,
    response_model=SuccessResponse[GetMe],
    responses={**DEFAULT_RESPONSES }
)
async def get_me(request: Request, user: GetMe = Depends(get_current_user)):
    """
        Retrieve the currently authenticated user's profile.

        Returns:
            The current user's ID and role.
    """

    result = await profile_service.get_me(request=request, current_user=user)
    return SuccessResponse(data=result, message="Successfully retrieved")


@auth_router.patch(
    "/change_password/{user_id}",
    status_code=204,
    responses={**DEFAULT_RESPONSES }
)
async def change_password(
        request:Request,
        password_request :AuthChangePassword,
        user_id : UUID,
        user : GetMe = Depends(get_current_user),
        session: AsyncSession = Depends(get_session)
):
    """
    Change the password of a specific user.

    - A user can change **only their own** password.
    - An **admin** can change the password for **any user**.
    - The current (old) password must be valid before updating.
    """


    await  profile_service.change_password_by_user_id(
        request=request,
        password_request=password_request,
        user_id=user_id,
        current_user=user,
        session=session
    )

    return Response(status_code=204)

@auth_router.patch(
    "/change_role/{user_id}",
    status_code=204,
    responses={**DEFAULT_RESPONSES}
)
async def change_role(
        request:Request,
        user_id : UUID,
        change_role_data : AuthChangeRole,
        user : GetMe = Depends(get_current_user),
        session: AsyncSession = Depends(get_session)
):
    """
    Change the role of a specific user.

    - A user can change **only their own** role.
    - An **admin** can change the role of **any user**.
    - Role will not be changed if it's already the same.
    """


    await profile_service.change_role_by_user_id(
        request=request,
        user_id=user_id,
        change_role_data=change_role_data,
        current_user=user,
        session=session
    )

    return Response(status_code=204)