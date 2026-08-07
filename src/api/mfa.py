from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.dependencies import (
    get_mfa_service,
    get_user_auth_service,
    get_user_from_access_token,
)
from api.response_models import MfaResendRequest, MfaResendResponse, MfaSetupRequest
from repos.user_repository import User
from services.auth_service import UserAuthService
from services.exceptions import MFAException, UserNotFoundException
from services.mfa_service import MfaLoginCode, MFAService
from services.token_service import TokenPair


router = APIRouter(prefix="/mfa")


@router.post("/login", response_model=TokenPair)
def confirm_mfa_login(
    body: MfaLoginCode,
    user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)],
):
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


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def setup_mfa(
    body: MfaSetupRequest,
    user: Annotated[User, Depends(get_user_from_access_token)],
    mfa_service: Annotated[MFAService, Depends(get_mfa_service)],
):
    try:
        mfa_service.setup_mfa(user.id, body.phone_number)
    except MFAException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return {"message": "MFA set up successfully"}


@router.post("/resend-mfa-code", status_code=status.HTTP_200_OK, response_model=MfaResendResponse)
def resend_mfa_code(body: MfaResendRequest,
                    mfa_service: Annotated[MFAService, Depends(get_mfa_service)]):
    try:
        new_code: MfaLoginCode = mfa_service.resend_mfa_code(body.request_id)
    except MFAException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return MfaResendResponse(request_id=new_code.id)