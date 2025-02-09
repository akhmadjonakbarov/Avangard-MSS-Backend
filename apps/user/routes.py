from typing import Annotated
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field
from starlette import status
from .scheme import CreateUserRequest
from .serializers import UserModelSerializer
from apps.user.models import User
from di.db import db_dependency
from core.security import verify_password, get_password_hash, create_access_token

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

oauth2_bearer = OAuth2PasswordBearer(
    tokenUrl='/api/v1/auth/token',
)


class LoginRequest(BaseModel):
    email: str = Field(min_length=6)
    password: str = Field(min_length=6)


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(db: db_dependency, login_req: LoginRequest):
    user: User = db.query(User).filter(login_req.email == User.email and verify_password(
        login_req.password) == User.password).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect username or password"
        )

    access_token = create_access_token(
        email=user.email, user_id=user.id
    )

    serializer = UserModelSerializer(many=False)
    serialized_user = serializer.dump(user)
    serialized_user['token'] = access_token

    return {'user': serialized_user}


@router.post("/register")
async def register(
        db: db_dependency, created_user_body: CreateUserRequest,

):
    try:
        with db.begin():
            created_user = User(
                email=created_user_body.email,
                first_name=created_user_body.first_name,
                last_name=created_user_body.last_name,
                password=get_password_hash(created_user_body.password)
            )
            db.add(created_user)
            db.flush()
            access_token = create_access_token(
                email=created_user.email, user_id=created_user.id
            )

            serializer = UserModelSerializer(many=False)
            serialized_user = serializer.dump(created_user)
            serialized_user['token'] = access_token

            return {'user': serialized_user}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user: User = db.query(User).filter(
        User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")
    return {"access_token": create_access_token(user.email, user.id)}
