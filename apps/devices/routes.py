from fastapi import APIRouter

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from .models import DeviceModel
from .schemes import DeviceCreate, DeviceResponse
from di.db import db_dependency
from di.user import user_dependency

router = APIRouter(
    prefix='/devices',
    tags=['Device Manager']

)


# Create a new device
@router.post("/add", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
def create_device(db: db_dependency, device: DeviceCreate):
    with db.begin():
        db_device = db.query(DeviceModel).filter(DeviceModel.device_code == device.device_code).first()
        if db_device:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device with this code already exists")
        new_device = DeviceModel(**device.dict())
        db.add(new_device)

    db.refresh(new_device)
    return {'message': 'success'}


# Get all devices
@router.get("/all", response_model=List[DeviceResponse], status_code=status.HTTP_200_OK)
def get_devices(db: db_dependency, user: user_dependency):
    devices = db.query(DeviceModel).all()
    return devices


# Get a single device by ID


# Update a device
@router.patch("/update/{device_id}", response_model=DeviceResponse)
def update_device(device_id: int, updated_device: DeviceCreate, db: db_dependency, user: user_dependency):
    device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    for key, value in updated_device.dict().items():
        setattr(device, key, value)

    db.commit()
    db.refresh(device)
    return device


# Delete a device
@router.delete("/delete/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(device_id: int, db: db_dependency, user: user_dependency):
    device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    db.delete(device)
    db.commit()
    return {"message": "Device deleted successfully"}
