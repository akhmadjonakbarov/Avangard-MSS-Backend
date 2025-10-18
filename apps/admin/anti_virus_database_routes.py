from fastapi import APIRouter, HTTPException
from sqlalchemy.future import select

from apps.admin.serializers.device_serializer import (
    AppCreate, AppRead,
    MalwareRead, MalwareCreate,
    DetectionRead, DetectionCreate
)
from apps.antivirus.models import Malware, Detection, App
from di.db import db_dependency
from di.user import admin_dependency

router = APIRouter()


@router.post("/apps/", response_model=AppRead)
async def create_app(
        app_in: AppCreate, db: db_dependency, admin: admin_dependency
):
    app = App(
        application_id=app_in.application_id,
        file_hash=app_in.file_hash,
        total_engines=app_in.total_engines,
        malicious_count=app_in.malicious_count,
        suspicious_count=app_in.suspicious_count,
        harmless_count=app_in.harmless_count,
        undetected_count=app_in.undetected_count,
        scan_date=app_in.scan_date,
    )

    if app_in.malware_ids:
        result = await db.execute(
            select(Malware).where(Malware.id.in_(app_in.malware_ids))
        )
        app.malwares = result.scalars().all()

    db.add(app)
    await db.commit()
    await db.refresh(app)
    return app


@router.get("/apps/{app_id}", response_model=AppRead)
async def get_app(app_id: int, db: db_dependency, admin: admin_dependency):
    result = await db.execute(select(App).where(App.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    return app


@router.get("/apps/", response_model=list[AppRead])
async def list_apps(db: db_dependency, admin: admin_dependency):
    result = await db.execute(select(App))
    return result.scalars().all()


@router.delete("/apps/{app_id}")
async def delete_app(app_id: int, db: db_dependency, admin: admin_dependency):
    result = await db.execute(select(App).where(App.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    await db.delete(app)
    await db.commit()
    return {"detail": "App deleted"}


# -------------------- MALWARE CRUD --------------------
@router.post("/malwares/", response_model=MalwareRead)
async def create_malware(malware_in: MalwareCreate, db: db_dependency, admin: admin_dependency):
    malware = Malware(**malware_in.dict())
    db.add(malware)
    await db.commit()
    await db.refresh(malware)
    return malware


@router.get("/malwares/{malware_id}", response_model=MalwareRead)
async def get_malware(malware_id: int, db: db_dependency, admin: admin_dependency):
    result = await db.execute(select(Malware).where(Malware.id == malware_id))
    malware = result.scalar_one_or_none()
    if not malware:
        raise HTTPException(status_code=404, detail="Malware not found")
    return malware


@router.get("/malwares/", response_model=list[MalwareRead])
async def list_malwares(db: db_dependency, admin: admin_dependency):
    result = await db.execute(select(Malware))
    return result.scalars().all()


# -------------------- DETECTION CRUD --------------------
@router.post("/detections/", response_model=DetectionRead)
async def create_detection(detection_in: DetectionCreate, db: db_dependency, admin: admin_dependency):
    detection = Detection(**detection_in.dict())
    db.add(detection)
    await db.commit()
    await db.refresh(detection)
    return detection
