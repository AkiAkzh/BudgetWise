from sqlalchemy.future import select  # или просто from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from microservices.main_app.api.auth.models.auth import Auth

from uuid import UUID

from microservices.main_app.api.auth.schemas.auth_schema import AuthChangeRole

async def create_user(email: str, hashed_password: str, session: AsyncSession) -> Auth:
    user = Auth(
        email=email,
        hashed_password=hashed_password
    )

    session.add(user)
    await session.commit()
    await session.refresh(user)

    return user

async def update_refresh_token(user_id: UUID, new_refresh_token : str|None,session: AsyncSession) -> None:
    statement = select(Auth).where(Auth.id == user_id)
    result = await session.execute(statement)
    user : Auth = result.scalar_one_or_none()

    if user :
        user.refresh_token = new_refresh_token
        session.add(user)
        await session.commit()


async def get_user_by_email(email: str, session: AsyncSession) -> Auth | None:
    statement = select(Auth).where(Auth.email == email)
    result = await session.execute(statement)
    return result.scalars().first()

async def get_user_by_id(user_id: UUID, session: AsyncSession) -> Auth | None:
    statement = select(Auth).where(Auth.id == user_id)
    result = await session.execute(statement)
    return result.scalars().first()

async def get_user_by_refresh_token(refresh_token: str, session: AsyncSession) -> Auth | None:
    statement = select(Auth).where(Auth.refresh_token == refresh_token)
    result = await session.execute(statement)
    return result.scalars().first()

async def update_password_by_user_id(user_id: UUID, new_password: str, session: AsyncSession) -> Auth | None:
    statement = select(Auth).where(Auth.id == user_id)
    result = await session.execute(statement)
    user : Auth = result.scalar_one_or_none()

    if user:
        user.hashed_password = new_password
        session.add(user)
        await session.commit()
        return user

    return None

async def update_role_by_user_id(user_id: UUID, change_role_request: AuthChangeRole, session: AsyncSession) -> Auth | None:
    statement = select(Auth).where(Auth.id == user_id)
    result = await session.execute(statement)
    user : Auth = result.scalar_one_or_none()

    if user:
        user.role = change_role_request.new_role
        session.add(user)
        await session.commit()
        return user