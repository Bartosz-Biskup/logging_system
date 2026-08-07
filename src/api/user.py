from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from api.response_models import (
    RequestPasswordResetBody,
    ResetPasswordBody,
    UpdateEmailRequest,
    UpdatePasswordRequest,
    UpdateUsernameRequest,
    UserRegisterRequest,
    UserResponseModel,
)
from repos.user_repository import User, UserRepository
from services.auth_service import UserAuthService
from services.exceptions import (
    InvalidPasswordException,
    MFAException,
    NotAuthenticatedException,
    UserAlreadyRegisteredException,
    UserNotFoundException,
)
from services.mfa_service import MfaLoginCode
from services.password_reset_service import PasswordResetService
from services.token_service import TokenPair
from services.user_service import UserService
from api.dependencies import (
    get_password_reset_service,
    get_user_auth_service,
    get_user_from_access_token,
    get_user_repo,
    get_user_service,
)


router = APIRouter(prefix="")


@router.post("/users/register", response_model=UserResponseModel)
def register(body: UserRegisterRequest,
             user_service: Annotated[UserService, Depends(get_user_service)]):
    try:
        new_user: User = user_service.register_user(username=body.username,
                                                    email=body.email,
                                                    password=body.password)
    except UserAlreadyRegisteredException:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="User with this username or email is already registered")
    except InvalidPasswordException:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="Invalid Password, make sure password contains"
                            "at least one uppercase letter, one lowercase letter, "
                            "one digit and one special character and"
                            "its length is between 8 and 255")

    return UserResponseModel.model_validate(new_user,
                                            from_attributes=True)


@router.get("/users/get/{username}", response_model=UserResponseModel)
def get_user(username: str,
             user_repo: Annotated[UserRepository, Depends(get_user_repo)]):
    user: User | None = user_repo.get_user_by_username(username)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found")

    return UserResponseModel.model_validate(user, from_attributes=True)


@router.patch("/users/email", response_model=UserResponseModel)
def update_email(
    body: UpdateEmailRequest,
    user: Annotated[User, Depends(get_user_from_access_token)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    try:
        updated_user = user_service.update_email(user.id, body.new_email)
    except UserNotFoundException:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except UserAlreadyRegisteredException:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already taken")
    return updated_user


@router.patch("/users/username", response_model=UserResponseModel)
def update_username(
    body: UpdateUsernameRequest,
    user: Annotated[User, Depends(get_user_from_access_token)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    try:
        updated_user = user_service.update_username(user.id, body.new_username)
    except UserNotFoundException:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except UserAlreadyRegisteredException:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username is already taken")
    return updated_user

@router.patch("/users/password", response_model=UserResponseModel)
def update_password(
    body: UpdatePasswordRequest,
    user: Annotated[User, Depends(get_user_from_access_token)],
    user_service: Annotated[UserService, Depends(get_user_service)]
):
    try:
        updated_user: User = user_service.change_password(user.id, 
                                                               body.current_password, 
                                                               body.new_password)
    except NotAuthenticatedException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User unauthorized")
    except InvalidPasswordException:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="Invalid new password. Check our password guidelines.")

    return updated_user


@router.post("/users/password-reset/request", status_code=status.HTTP_200_OK)
def request_password_reset(body: RequestPasswordResetBody,
                           password_reset_service: Annotated[PasswordResetService, Depends(get_password_reset_service)]):
    try:
        password_reset_service.generate_and_send_password_reset_link(body.email)
    except ValueError:
        # Swallow on purpose so we always return the same generic message
        # (prevents email enumeration)
        pass

    return {
        "message": "If the account exists, a password reset link has been sent"
    }


@router.post("/users/password-reset/reset", status_code=status.HTTP_200_OK)
def reset_password(body: ResetPasswordBody,
                   password_reset_service: Annotated[PasswordResetService, Depends(get_password_reset_service)]):
    try:
        password_reset_service.reset_password_with_reset_request(body.reset_request_id,
                                                                 body.new_password)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid or expired reset request")
    except InvalidPasswordException:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="Invalid new password. Check our password guidelines.")

    return {
        "message": "Password has been reset successfully"
    }

@router.post("/users/login/mfa", response_model=TokenPair)
def confirm_mfa_login(body: MfaLoginCode,
                      user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        return user_auth_service.confirm_mfa(body)
    except MFAException:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid or expired MFA code",
        )
    except UserNotFoundException:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
