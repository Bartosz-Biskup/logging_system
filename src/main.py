from datetime import datetime
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine
from os import getenv
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, Field
from repos.user_repository import User, AccountState, UserRepository
from services.exceptions import InvalidPasswordException, UserAlreadyRegisteredException
from services.user_service import UserService


app = FastAPI()


load_dotenv()


DATABASE_URL = f"mysql+mysqlconnector://root:{getenv("DB_PASSWORD")}@localhost:3306/logging_system"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine, autocommit=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except:
        db.rollback()
        raise
    finally:
        db.close()


def get_user_repo(db: Session = Depends(get_db)):
    return UserRepository(db)


def get_user_service(user_repo = Depends(get_user_repo)):
    return UserService(user_repo)


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


@app.post("/users/register", response_model=UserResponseModel)
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


