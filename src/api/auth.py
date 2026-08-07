from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPAuthorizationCredentials
from typing import Annotated
from services.exceptions import NotAuthenticatedException
from services.auth_service import LoginResponse, UserAuthService, LoginResponse
from api.dependencies import get_user_auth_service, http_bearer
from api.response_models import UserLoginRequest


router = APIRouter(prefix='/auth')


@router.post("/login", response_model=LoginResponse)
def login(body: UserLoginRequest,
          user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        return user_auth_service.login(body.email, body.password)
    except NotAuthenticatedException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")


@router.post("/logout")
def logout(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
           user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        user_auth_service.logout(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User not authorized")

    return {
        "message": "success"
    }


@router.post("/logout-all")
def logout_all(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
               user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        user_auth_service.logout_all(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User not authorized")

    return {
        "message": "success"
    }


@router.post("/rotate_tokens")
def rotate_tokens(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
                  user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        user_auth_service.refresh_token_pair(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail="User not authorized")

    return {
        "message": "success"
    }