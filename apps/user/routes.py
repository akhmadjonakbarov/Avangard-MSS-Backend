from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import Annotated
from sqlalchemy import select

from apps import User
from apps.user.scheme import RegisterRequest
from apps.user.serializers import UserModelSerializer
from core.security import verify_password, create_access_token, get_password_hash
from di.db import db_dependency

# Admin router
admin_router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

# OAuth2 scheme for admin token
# This points to your admin token endpoint
admin_oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")


# Admin request models
class LoginRequest(BaseModel):
    email: str = Field(min_length=6)
    password: str = Field(min_length=6)


@admin_router.post("/login", status_code=status.HTTP_200_OK)
async def login(
        db: db_dependency,
        login_req: LoginRequest,
):
    result = await db.execute(
        select(User).where(User.email == login_req.email)
    )
    user: User | None = result.scalar_one_or_none()

    if not user or not verify_password(login_req.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect credentials"
        )

    print(str(user))
    access_token = create_access_token(email=user.email, user_id=user.id, is_admin=user.is_admin)

    serializer = UserModelSerializer(many=False)
    serialized_user = serializer.dump(user)
    serialized_user['token'] = access_token

    return {'user': serialized_user}


# Admin token endpoint for OAuth2
@admin_router.post("/token")
async def token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: db_dependency
):
    result = await db.execute(
        select(User).where(User.email == form_data.username)
    )
    admin: User | None = result.scalar_one_or_none()

    if not admin or not verify_password(form_data.password, admin.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect admin credentials"
        )

    return {
        "access_token": create_access_token(admin.email, admin.id, is_admin=admin.is_admin),
        "token_type": "bearer"
    }


# Admin registration
@admin_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
        db: db_dependency,
        admin_req: RegisterRequest
):
    key = "enable_admin"
    try:
        async with db.begin():
            new_admin = User(
                email=admin_req.email,
                first_name=admin_req.first_name,
                last_name=admin_req.last_name,
                password=get_password_hash(admin_req.password),
                is_admin=True if key == admin_req.admin_key else False  # mark as admin
            )
            db.add(new_admin)

        await db.refresh(new_admin)

        access_token = create_access_token(
            email=new_admin.email,
            user_id=new_admin.id,
            is_admin=True
        )

        serializer = UserModelSerializer(many=False)
        serialized_admin = serializer.dump(new_admin)
        serialized_admin['token'] = access_token

        return {'admin': serialized_admin}

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
