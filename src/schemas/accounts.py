from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators, UserGroupEnum
from database.validators.accounts import validate_email, \
    validate_password_strength


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    def email_validator(cls, value):
        return validate_email(value)


class UserRegistrationRequestSchema(UserBase):
    password: str
    group_id: int = 1

    @field_validator("password")
    def password_validator(cls, value):
        return validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = {"from_attributes": True}


class UserActivationRequestSchema:
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema:
    pass


class PasswordResetCompleteRequestSchema:
    pass


class UserLoginResponseSchema:
    pass


class UserLoginRequestSchema:
    pass


class TokenRefreshRequestSchema:
    refresh_token: str


class TokenRefreshResponseSchema:
    access_token: str
    token_type: str
