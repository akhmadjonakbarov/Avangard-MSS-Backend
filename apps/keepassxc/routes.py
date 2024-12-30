from fastapi import APIRouter, HTTPException, Path
from starlette import status
from .schemes import CredentialRequestBody
from apps.keepassxc.models import CredentialModel
from di.db import db_dependency
from di.user import user_dependency

router = APIRouter(
    prefix='/keepass',
    tags=['KeePass Manager']
)


@router.get('/all')
async def get_credentials(db: db_dependency, user: user_dependency):
    try:
        credentials = db.query(CredentialModel).filter_by(user_id=user.get('id'))
        return {'credentials': credentials}
    except Exception as e:
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_400_BAD_REQUEST
        )


@router.post('/add', status_code=status.HTTP_201_CREATED)
async def add_credential(db: db_dependency, user: user_dependency, credential_data: CredentialRequestBody):
    try:
        with db.begin():
            credential = CredentialModel(
                data=credential_data.data, user_id=user.get('id')
            )
            db.add(credential)
            return {'message': 'success'}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            detail=str(e), status_code=status.HTTP_400_BAD_REQUEST
        )


@router.patch('/update/{credential_id}', status_code=status.HTTP_200_OK)
async def update_credential(
        db: db_dependency, user: user_dependency, credential_data: CredentialRequestBody,
        credential_id=Path(gt=0)
):
    try:
        with db.begin():
            credential = db.query(CredentialModel).filter_by(id=credential_id).first()
            if not credential:
                raise HTTPException(detail='Credential not found', status_code=status.HTTP_404_NOT_FOUND)
            credential.data = credential_data.data
        return {'message': 'success'}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_400_BAD_REQUEST
        )


@router.delete('/delete/{credential_id}', status_code=status.HTTP_200_OK)
async def delete_credential(db: db_dependency, user: user_dependency, credential_id=Path(gt=0)):
    try:
        with db.begin():
            credential = db.query(CredentialModel).filter_by(id=credential_id, user_id=user.get('id')).first()
            if not credential:
                raise HTTPException(detail='Credential not found', status_code=status.HTTP_404_NOT_FOUND)
            db.delete(credential)
        return {'message': 'success'}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            detail=str(e), status_code=status.HTTP_502_BAD_GATEWAY
        )
