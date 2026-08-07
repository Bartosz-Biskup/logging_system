"""Request and response models for the API."""

from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from repos.user_repository import AccountState
from services.config import MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH


class UserRegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr = Field(max_length=120)
    password: str = Field(min_length=8, max_length=256)


class UserResponseModel(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr = Field(max_length=120)
    account_state: AccountState
    role: str = Field(max_length=20)
    created_at: datetime


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(max_length=120)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH,
                          max_length=MAX_PASSWORD_LENGTH)


class UpdateEmailRequest(BaseModel):
    new_email: EmailStr = Field(max_length=120)


class UpdateUsernameRequest(BaseModel):
    new_username: str = Field(min_length=3, max_length=50)


class UpdatePasswordRequest(BaseModel):
    current_password: str = Field(min_length=MIN_PASSWORD_LENGTH,
                                  max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH,
                              max_length=MAX_PASSWORD_LENGTH)


class RequestPasswordResetBody(BaseModel):
    email: EmailStr = Field(max_length=120)


class ResetPasswordBody(BaseModel):
    reset_request_id: str = Field(min_length=36, max_length=36)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH,
                              max_length=MAX_PASSWORD_LENGTH)


class MfaSetupRequest(BaseModel):
    phone_number: str