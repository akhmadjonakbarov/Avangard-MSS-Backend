from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.exc import SQLAlchemyError

from di.db import db_dependency
from di.user import admin_dependency
from .models import Version
from .schemes import VersionRequest, VersionResponse

router = APIRouter(
    prefix="/versions",
    tags=["App Versions"]
)


@router.post("/add", status_code=status.HTTP_201_CREATED, response_model=VersionResponse)
async def create_version(
        db: db_dependency,
        admin:admin_dependency,
        version: VersionRequest,
):
    try:
        new_version = Version(**version.model_dump())
        db.add(new_version)
        await db.commit()
        await db.refresh(new_version)
        return new_version
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {e}"
        )


@router.get("/", response_model=list[VersionResponse])
async def get_versions(db: db_dependency, admin:admin_dependency,):
    result = await db.execute(select(Version))
    versions = result.scalars().all()
    return versions


@router.get("/latest", response_model=VersionResponse)
async def get_latest_version(db: db_dependency):
    result = await db.execute(select(Version).order_by(desc(Version.id)))
    latest_version = result.scalars().first()
    if not latest_version:
        raise HTTPException(status_code=404, detail="No versions found")
    return latest_version




@router.patch("/update/{version_id}", response_model=VersionResponse)
async def update_version(version_id: int, updated: VersionRequest, db: db_dependency, admin:admin_dependency,):
    result = await db.execute(select(Version).where(Version.id == version_id))
    version = result.scalar_one_or_none()
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    for field, value in updated.model_dump(exclude_unset=True).items():
        setattr(version, field, value)

    try:
        await db.commit()
        await db.refresh(version)
        return version
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


@router.delete("/delete/{version_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_version(version_id: int, db: db_dependency, admin:admin_dependency,):
    result = await db.execute(select(Version).where(Version.id == version_id))
    version = result.scalar_one_or_none()
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    try:
        await db.delete(version)
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
