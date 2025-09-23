from fastapi import APIRouter, HTTPException, Path, Body, Depends
from starlette import status
from sqlalchemy import select
from .schemes import CredentialRequestBody
from apps.safe_password.models import Credential
from di.db import db_dependency
from di.user import user_dependency
from .serializers import CredentialSerializer

router = APIRouter(
    prefix='/safe-passwords',
    tags=['KeePass Manager']
)


# Get all credentials
@router.get('/all')
async def get_credentials(
        db: db_dependency,
        user: user_dependency
):
    try:
        result = await db.execute(
            select(Credential).where(Credential.user_id == user.get('id'))
        )
        credentials = result.scalars().all()
        serializer = CredentialSerializer(many=True)
        return {'credentials': serializer.dump(credentials)}
    except Exception as e:
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_400_BAD_REQUEST
        )


# Create a credential
@router.post('/create', status_code=status.HTTP_201_CREATED)
async def add_credential(
        db: db_dependency,
        user: user_dependency,
        credential_data: CredentialRequestBody = Body(...)
):
    try:
        async with db.begin():
            credential = Credential(
                data=credential_data.credential_data,
                user_id=user.get('id')
            )
            db.add(credential)
        return {'message': 'success'}
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            detail=str(e), status_code=status.HTTP_400_BAD_REQUEST
        )


# Update a credential
@router.patch('/update/{credential_id}', status_code=status.HTTP_200_OK)
async def update_credential(
        db: db_dependency,
        user: user_dependency,
        credential_id: int = Path(...),
        credential_data: CredentialRequestBody = Body(...)
):
    try:
        async with db.begin():
            result = await db.execute(
                select(Credential).where(Credential.id == credential_id)
            )
            credential = result.scalar_one_or_none()

            if not credential:
                raise HTTPException(
                    detail='Credential not found',
                    status_code=status.HTTP_404_NOT_FOUND
                )

            credential.data = credential_data.credential_data

        return {'message': 'success'}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_400_BAD_REQUEST
        )


# Delete a credential
@router.delete('/delete/{credential_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(db: db_dependency,
                            user: user_dependency,
                            credential_id: int = Path(...),

                            ):
    try:
        async with db.begin():
            result = await db.execute(
                select(Credential).where(
                    Credential.id == credential_id,
                    Credential.user_id == user.get('id')
                )
            )
            credential = result.scalar_one_or_none()

            if not credential:
                raise HTTPException(
                    detail='Credential not found',
                    status_code=status.HTTP_404_NOT_FOUND
                )

            await db.delete(credential)

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_502_BAD_GATEWAY
        )
