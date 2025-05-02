from uuid import UUID

from fastapi import APIRouter, Request, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from libs.common_models import SuccessResponse
from microservices.main_app.api.auth.schemas.auth_schema import AuthLogin, AuthTokenResponse, GetMe, \
    RefreshTokenRequest, AuthChangePassword, AuthChangeRole, AuthRegister
from microservices.main_app.api.auth.services import auth_service
from microservices.main_app.core.database import get_session
from microservices.main_app.core.security import get_current_user

auth_router = APIRouter()

@auth_router.post("/register", status_code=201, response_model=SuccessResponse[AuthTokenResponse])
async def register_auth(
        request: Request,
        register_data: AuthRegister,
        session: AsyncSession = Depends(get_session)
):
    result = await auth_service.register(
        request=request,
        register_data=register_data,
        session=session,
    )
    return SuccessResponse(
        data=result,
        message=f"Registered successfully!",
    )


@auth_router.post("/login", response_model=SuccessResponse[AuthTokenResponse])
async def login(request: Request, login_data : AuthLogin,
    session: AsyncSession = Depends(get_session)):

    result = await auth_service.auth_login(request=request, user_data=login_data, session=session)

    return SuccessResponse(data=result, message="Successfully logged in")
@auth_router.post("/logout", status_code=204)
async def logout(
        request: Request,
        session: AsyncSession = Depends(get_session),
        user : GetMe = Depends(get_current_user)
):

    await auth_service.logout(request=request, session=session, current_user=user)
    return Response(status_code=204)

@auth_router.post("/refresh", status_code=200, response_model=SuccessResponse[AuthTokenResponse])
async def refresh(
        request : Request,
        refresh_token : RefreshTokenRequest,
        user : GetMe = Depends(get_current_user),
        session: AsyncSession = Depends(get_session)
):


    result = await auth_service.refresh_access_token(request=request, refresh_token=refresh_token, session=session, current_user=user)
    return SuccessResponse(data=result, message="Successfully refreshed")

@auth_router.get("/me", status_code=200, response_model=SuccessResponse[GetMe])
async def get_me(request: Request, user: GetMe = Depends(get_current_user)):

    result = await auth_service.get_me(request=request, current_user=user)
    return SuccessResponse(data=result, message="Successfully retrieved")


@auth_router.patch("/change_password/{user_id}", status_code=204)
async def change_password(
        request:Request,
        password_request :AuthChangePassword,
        user_id : UUID,
        user : GetMe = Depends(get_current_user),
        session: AsyncSession = Depends(get_session)
):

    await  auth_service.change_password_by_user_id(
        request=request,
        password_request=password_request,
        user_id=user_id,
        current_user=user,
        session=session
    )

    return Response(status_code=204)

@auth_router.patch("/change_role/{user_id}", status_code=204)
async def change_role(
        request:Request,
        user_id : UUID,
        change_role_data : AuthChangeRole,
        user : GetMe = Depends(get_current_user),
        session: AsyncSession = Depends(get_session)
):

    await auth_service.change_role_by_user_id(
        request=request,
        user_id=user_id,
        change_role_data=change_role_data,
        current_user=user,
        session=session
    )

    return Response(status_code=204)