from fastapi import APIRouter
from starlette.exceptions import HTTPException
from starlette import status

from apps.antivirus.models import Malware
from di.db import db_dependency

router = APIRouter(
    prefix='/antivirus-database',
    tags=['AntiVirus']
)


@router.get('/init')
async def init(db: db_dependency):
    try:
        scanned_apps = db.query(Malware).all()
        return {'apps': scanned_apps}
    except Exception as e:
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_400_BAD_REQUEST
        )


@router.post('/scan')
async def scan():
    pass
