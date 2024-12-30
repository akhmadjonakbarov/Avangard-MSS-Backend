from fastapi import APIRouter

router = APIRouter(
    prefix='/antivirus-database'
)

router.get('/init')
async def init():
    pass

