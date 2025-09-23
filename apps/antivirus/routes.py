import asyncio
import hashlib
import logging
from typing import Optional

import aiohttp
from fastapi import APIRouter, UploadFile, File, Form, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database_config import async_session_factory
from .models import App, Malware, ScanTask, ScanStatus
from .serializers import AppSerializer
from .repositories import VirusTotalRepository
from di.db import db_dependency
from di.device import device_dependency  # device_code dependency

router = APIRouter(
    prefix='/antivirus-database',
    tags=['AntiVirus']
)

# Configure logging
logger = logging.getLogger("antivirus")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# VirusTotal rate limiting (4 requests per minute)
vt_semaphore = asyncio.Semaphore(4)
VT_WAIT_SECONDS = 15  # 4 requests/minute → 1 request every 15 seconds


@router.post("/scan")
async def scan_file(
        db: db_dependency,
        device: device_dependency,
        file: UploadFile = File(...),
        application_id: str = Form(...),
):
    file_bytes = await file.read()


    # check if task already exists for this file + app
    query = select(ScanTask).where(
        ScanTask.application_id == application_id,
    )
    existing_task = (await db.execute(query)).scalars().first()

    if existing_task:
        logger.info(f"File alrady exist for scanning: {application_id}")
        raise HTTPException(
            status_code=status.HTTP_200_OK,
            detail={
                "message": "File already scanned",
                "task_id": existing_task.id,
                "status": existing_task.status,
            }
        )

    # create new scan task
    new_task = ScanTask(
        application_id=application_id,
        file_bytes=file_bytes,

        status=ScanStatus.pending,
        device_code=device.get("device_code"),
    )
    db.add(new_task)
    await db.commit()
    await db.refresh(new_task)
    logger.info(f"New Task: {new_task.id} {new_task.status} {application_id}")
    return {
        "message": "New scan task created",
        "task_id": new_task.id,
        "status": new_task.status,
    }


async def process_scan_file(device_code: str, file_bytes: bytes, application_id: str, filename: str):
    repo = VirusTotalRepository()

    async with async_session_factory() as db:
        try:
            # Step 1: Upload file to VirusTotal
            async with vt_semaphore:  # Respect VT rate limit
                vt_resp = await repo.scan_file(file_bytes, filename)
                await asyncio.sleep(VT_WAIT_SECONDS)

            analysis_id = vt_resp.get("data", {}).get("id")
            if not analysis_id:
                logger.error(f"Failed scan for app={application_id}, device={device_code}")
                return

            # Step 2: Poll until scan completes
            for _ in range(30):
                report = await repo.get_report(analysis_id)
                status_attr = report.get("data", {}).get("attributes", {}).get("status")
                if status_attr == "completed":
                    # Step 3: Save scan result
                    await save_scan_result(report, db, application_id)
                    # Step 4: Send notification
                    await send_notification(device_code, report)
                    logger.info(f"Completed scan for app={application_id}, device={device_code}")
                    break
                await asyncio.sleep(2)
            else:
                logger.warning(f"Timeout for scan app={application_id}, device={device_code}")

        except Exception as e:
            logger.exception(f"Error during scan for app={application_id}, device={device_code}: {e}")


async def save_scan_result(report: dict, db: AsyncSession, application_id: str):
    """
    Extract malicious engines, save App, Malware, and Detection records, associate them.
    """
    results = report.get("data", {}).get("attributes", {}).get("results", {})

    query = await db.execute(select(App).where(App.application_id == application_id))
    app_obj = query.scalars().first()
    if not app_obj:
        app_obj = App(application_id=application_id)
        db.add(app_obj)
        await db.commit()
        await db.refresh(app_obj)
        logger.info(f"App created: {application_id}")

    for engine_name, engine_result in results.items():
        category = engine_result.get("category")
        result_str = engine_result.get("result")

        if category == "malicious" and result_str:
            # 1. Check/create Malware
            query = await db.execute(select(Malware).where(Malware.name == result_str))
            malware_obj = query.scalars().first()
            if not malware_obj:
                malware_obj = Malware(name=result_str)
                db.add(malware_obj)
                await db.commit()
                await db.refresh(malware_obj)
                logger.info(f"Malware created: {result_str}")

            # Link Malware to App if not linked
            if malware_obj not in app_obj.malwares:
                app_obj.malwares.append(malware_obj)

            # 2. Add Detection
            from .models import Detection  # ensure you import Detection
            detection = Detection(
                engine_name=engine_name,
                engine_version=engine_result.get("engine_version"),
                category=category,
                result=result_str,
                malware=malware_obj
            )
            db.add(detection)
            await db.commit()
            await db.refresh(detection)
            logger.info(f"Detection added: {engine_name} -> {result_str}")

    await db.commit()
    logger.info(f"Scan result saved for app={application_id}")


async def send_notification(device_code: str, report: dict):
    """
    Send POST request to device with scan results.
    """
    import httpx
    device_endpoint = f"https://example.com/device/{device_code}/notify"
    try:
        async with httpx.AsyncClient() as client:
            await client.post(device_endpoint, json={"report": report})
        logger.info(f"Notification sent to device {device_code}")
    except Exception as e:
        logger.error(f"Failed to send notification to device {device_code}: {e}")


@router.get("/init")
async def init(db: db_dependency):
    try:
        result = await db.execute(select(App))
        apps = result.scalars().all()
        serializer = AppSerializer(many=True)
        logger.info(f"/init returned {len(apps)} apps")
        return {"apps": serializer.dump(apps)}
    except Exception as e:
        logger.exception(f"/init error: {e}")
        raise HTTPException(detail=str(e), status_code=status.HTTP_400_BAD_REQUEST)


async def scan_worker():
    repo = VirusTotalRepository()
    while True:
        async with async_session_factory() as db:
            result = await db.execute(
                select(ScanTask).where(
                    ScanTask.status.in_([ScanStatus.pending, ScanStatus.timeout, ScanStatus.processing]))
            )
            tasks = result.scalars().all()

            for task in tasks:
                # Only mark as processing if it was pending or timeout
                if task.status in [ScanStatus.pending, ScanStatus.timeout]:
                    task.status = ScanStatus.processing
                    await db.commit()
                    await db.refresh(task)

                try:
                    vt_resp = await repo.scan_file(task.file_bytes, f"{task.application_id}.apk")
                    analysis_id = vt_resp.get("data", {}).get("id")

                    if not analysis_id:
                        task.status = ScanStatus.failed
                        await db.commit()
                        logger.warning(f"Task {task.application_id} FAILED (no analysis id)")
                        continue

                    # Poll for scan completion
                    for _ in range(80):
                        try:
                            report = await repo.get_report(analysis_id)
                            status_attr = report.get("data", {}).get("attributes", {}).get("status")
                            if status_attr == "completed":
                                await save_scan_result(report, db, task.application_id)
                                await send_notification(task.device_code, report)
                                await db.delete(task)
                                await db.commit()
                                logger.info(f"Task {task.application_id} COMPLETED successfully")
                                break
                        except aiohttp.ClientResponseError as e:
                            if e.status == 429:
                                # Keep task in processing state, retry later
                                logger.warning(f"Rate limited on {task.application_id}, retrying in 30s")
                                await asyncio.sleep(30)
                                continue  # retry the same poll
                            else:
                                raise  # Other HTTP errors are fatal

                        await asyncio.sleep(5)
                    else:
                        # Did not complete after max polls, mark timeout
                        task.status = ScanStatus.timeout
                        await db.commit()
                        logger.warning(f"Task {task.application_id} TIMEOUT after polling")

                except Exception as e:
                    # Only fatal errors mark the task as failed
                    logger.exception(f"Unexpected error for {task.application_id}: {e}")
                    task.status = ScanStatus.pending  # keep it pending for retry
                    await db.commit()

        await asyncio.sleep(5)


# Start worker on FastAPI startup
@router.on_event("startup")
async def start_worker():
    asyncio.create_task(scan_worker())
