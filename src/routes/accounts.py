from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pyexpat.errors import messages
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

import routes
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema, UserActivationRequestSchema,
    MessageResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
async def register(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_exist_result = await db.execute(select(UserModel).where(
        UserModel.email == user.email))
    if user_exist_result.scalars().first():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )

    try:
        new_user = UserModel.create(
            email=str(user.email),
            raw_password=user.password,
            group_id=user.group_id
        )

        db.add(new_user)
        await db.flush()

        access_token = ActivationTokenModel(user_id=new_user.id)
        db.add(access_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema.model_validate(new_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema
)
async def register(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    find_token_result = await db.execute(select(ActivationTokenModel)
    .options(
        joinedload(ActivationTokenModel.user)
    )
    .where(
        ActivationTokenModel.token == data.token,
        UserModel.email == data.email,
    ))
    this_token = find_token_result.scalars().first()
    this_user = this_token.user

    if this_token:

        if this_user.is_active:
            raise HTTPException(
                status_code=400,
                detail="User account is already active."
            )

        expires_date = cast(datetime, this_token.expires_at).replace(
            tzinfo=timezone.utc
        )
        if expires_date <= datetime.now(timezone.utc):
            this_user.is_active = True
            await db.commit()
            await db.refresh(this_user)

    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    return MessageResponseSchema(message="User account activated successfully.")


