import asyncio
import hashlib
import logging

import aiohttp
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database_config import async_session_factory
from core.exceptions import ScanTaskException
from di.db import db_dependency
from di.device import device_dependency
from .models import App, Malware, ScanTask, ScanStatus, Detection
from .repositories import VirusTotalRepository
from .serializers import AppSerializer

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

# VirusTotal rate limiting
vt_semaphore = asyncio.Semaphore(4)
VT_WAIT_SECONDS = 15  # 4 requests/minute → 1 request every 15 seconds


def calculate_file_hash(file_bytes: bytes) -> str:
    """Calculate SHA-256 hash of file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


@router.post("/scan")
async def scan_file(
        db: db_dependency,
        device: device_dependency,
        file: UploadFile = File(...),
        application_id: str = Form(...),
):
    file_bytes = await file.read()
    file_hash = calculate_file_hash(file_bytes)

    # Check if task already exists for this file hash + app
    query = select(ScanTask).where(
        ScanTask.application_id == application_id,
        ScanTask.scanning_hash == file_hash
    )
    existing_task = (await db.execute(query)).scalars().first()

    if existing_task:
        logger.info(f"File already exists for scanning: {application_id} with hash: {file_hash}")
        raise HTTPException(
            status_code=status.HTTP_200_OK,
            detail={
                "message": "File already scanned",
                "task_id": existing_task.id,
                "status": existing_task.status.value,
                "scanning_hash": file_hash
            }
        )

    # Check if app with same hash already exists (completed scan)
    app_query = select(App).where(App.file_hash == file_hash)
    existing_app = (await db.execute(app_query)).scalars().first()

    if existing_app:
        logger.info(f"File with same hash already completed scanning: {file_hash}")
        # Return existing scan results
        serializer = AppSerializer()
        return {
            "message": "File already scanned successfully",
            "status": "completed",
            "scanning_hash": file_hash,
            "app": serializer.dump(existing_app)
        }

    # Create new scan task
    new_task = ScanTask(
        application_id=application_id,
        file_bytes=file_bytes,
        scanning_hash=file_hash,
        status=ScanStatus.PENDING,
        device_code=device.get("device_code"),
    )
    db.add(new_task)
    await db.commit()
    await db.refresh(new_task)
    logger.info(f"New Task: {new_task.id} {new_task.status} {application_id} Hash: {file_hash}")
    return {
        "message": "New scan task created",
        "task_id": new_task.id,
        "status": new_task.status,
        "scanning_hash": file_hash
    }


@router.post("/scan/hash")
async def scan_by_hash(
        db: db_dependency,
        device: device_dependency,
        file_hash: str = Form(..., description="SHA-256 hash of the file"),
        application_id: str = Form(...),
):
    try:
        """Scan a file using only its hash (file already known to VirusTotal)."""

        # Check if app with this hash already exists
        app_query = select(App).where(App.file_hash == file_hash)
        existing_app = (await db.execute(app_query)).scalars().first()

        if existing_app:
            logger.info(f"File with hash already scanned: {file_hash}")
            serializer = AppSerializer()
            return {
                "message": "File already scanned successfully",
                "status": "completed",
                "scanning_hash": file_hash,
                "app": serializer.dump(existing_app)
            }

        # Check if task already exists for this hash
        task_query = select(ScanTask).where(
            ScanTask.scanning_hash == file_hash,
            ScanTask.application_id == application_id
        )
        existing_task = (await db.execute(task_query)).scalars().first()

        if existing_task:
            logger.info(f"Scan task already exists for hash: {file_hash}")
            raise HTTPException(
                status_code=status.HTTP_200_OK,
                detail={
                    "message": "Scan task already exists",
                    "task_id": existing_task.id,
                    "status": existing_task.status,
                    "scanning_hash": file_hash
                }
            )

        # Create hash-only scan task (no file bytes)
        new_task = ScanTask(
            application_id=application_id,
            file_bytes=b"",  # Empty bytes for hash-only scan
            scanning_hash=file_hash,
            status=ScanStatus.PENDING,
            device_code=device.get("device_code"),
        )
        db.add(new_task)
        await db.commit()
        await db.refresh(new_task)

        logger.info(f"New Hash-Only Task: {new_task.id} for {application_id} Hash: {file_hash}")
        return {
            "message": "Hash-based scan task created",
            "task_id": new_task.id,
            "status": new_task.status,
            "scanning_hash": file_hash
        }
    except Exception as e:
        print("ERROR: " + str(e))
        return {
            "detail": str(e)
        }


async def save_scan_result(report: dict, db: AsyncSession, application_id: str, file_hash: str):
    """
    Extract scan results and save to database.
    """
    attributes = report.get("data", {}).get("attributes", {})
    results = attributes.get("last_analysis_results", {}) or attributes.get("results", {})
    stats = attributes.get("last_analysis_stats", {})

    # Find or create App
    query = await db.execute(select(App).where(App.application_id == application_id))
    app_obj = query.scalars().first()

    if not app_obj:
        app_obj = App(application_id=application_id, file_hash=file_hash)
        db.add(app_obj)
        await db.commit()
        await db.refresh(app_obj)
        logger.info(f"App created: {application_id} with hash: {file_hash}")
    else:
        if not app_obj.file_hash:
            app_obj.file_hash = file_hash

    # Update scan statistics
    app_obj.total_engines = stats.get("total", 0)
    app_obj.malicious_count = stats.get("malicious", 0)
    app_obj.suspicious_count = stats.get("suspicious", 0)
    app_obj.harmless_count = stats.get("harmless", 0)
    app_obj.undetected_count = stats.get("undetected", 0)

    if attributes.get("last_analysis_date"):
        from datetime import datetime
        app_obj.scan_date = datetime.fromtimestamp(attributes["last_analysis_date"])

    # Process scan results
    malicious_found = False

    for engine_name, engine_result in results.items():
        category = engine_result.get("category")
        result_str = engine_result.get("result")

        if category in ["malicious", "suspicious"] and result_str:
            malicious_found = True

            # Find or create Malware
            malware_query = await db.execute(select(Malware).where(Malware.name == result_str))
            malware_obj = malware_query.scalars().first()

            if not malware_obj:
                malware_obj = Malware(name=result_str, category=category)
                db.add(malware_obj)
                await db.commit()
                await db.refresh(malware_obj)
                logger.info(f"Malware created: {result_str}")

            # Check if the relationship already exists by querying the association table
            from .models import app_malware
            link_query = await db.execute(
                select(app_malware).where(
                    app_malware.c.app_id == app_obj.id,
                    app_malware.c.malware_id == malware_obj.id
                )
            )
            existing_link = link_query.first()

            if not existing_link:
                # Only add if the relationship doesn't exist
                app_obj.malwares.append(malware_obj)
                logger.info(f"Linked malware {result_str} to app {application_id}")
            else:
                logger.info(f"Malware {result_str} already linked to app {application_id}")

            # Create Detection record
            detection = Detection(
                engine_name=engine_name,
                engine_version=engine_result.get("engine_version"),
                method=engine_result.get("method"),
                category=category,
                result=result_str,
                file_hash=file_hash,
                malware_id=malware_obj.id
            )
            db.add(detection)
            logger.info(f"Detection added: {engine_name} -> {result_str}")

    await db.commit()

    if malicious_found:
        logger.warning(f"MALICIOUS CONTENT FOUND for app={application_id}, hash={file_hash}")
    else:
        logger.info(f"Scan result saved - No threats found for app={application_id}, hash={file_hash}")


# async def save_scan_result(report: dict, db: AsyncSession, application_id: str, file_hash: str):
#     """
#     Extract scan results and save to database.
#     """
#     attributes = report.get("data", {}).get("attributes", {})
#     results = attributes.get("last_analysis_results", {}) or attributes.get("results", {})
#     stats = attributes.get("last_analysis_stats", {})
#
#     # Find or create App - DON'T load malwares relationship
#     query = await db.execute(select(App).where(App.application_id == application_id))
#     app_obj = query.scalars().first()
#
#     if not app_obj:
#         app_obj = App(application_id=application_id, file_hash=file_hash)
#         db.add(app_obj)
#         await db.commit()
#         await db.refresh(app_obj)
#         logger.info(f"App created: {application_id} with hash: {file_hash}")
#     else:
#         if not app_obj.file_hash:
#             app_obj.file_hash = file_hash
#
#     # Update scan statistics
#     app_obj.total_engines = stats.get("total", 0)
#     app_obj.malicious_count = stats.get("malicious", 0)
#     app_obj.suspicious_count = stats.get("suspicious", 0)
#     app_obj.harmless_count = stats.get("harmless", 0)
#     app_obj.undetected_count = stats.get("undetected", 0)
#
#     if attributes.get("last_analysis_date"):
#         from datetime import datetime
#         app_obj.scan_date = datetime.fromtimestamp(attributes["last_analysis_date"])
#
#     # Process scan results
#     malicious_found = False
#
#     for engine_name, engine_result in results.items():
#         category = engine_result.get("category")
#         result_str = engine_result.get("result")
#
#         if category in ["malicious", "suspicious"] and result_str:
#             malicious_found = True
#
#             # Find or create Malware
#             malware_query = await db.execute(select(Malware).where(Malware.name == result_str))
#             malware_obj = malware_query.scalars().first()
#
#             if not malware_obj:
#                 malware_obj = Malware(name=result_str, category=category)
#                 db.add(malware_obj)
#                 await db.commit()
#                 await db.refresh(malware_obj)
#                 logger.info(f"Malware created: {result_str}")
#
#             # SIMPLE FIX: Just append without checking if it exists
#             # SQLAlchemy will handle duplicate prevention in the many-to-many table
#             app_obj.malwares.append(malware_obj)
#
#             # Create Detection record
#             detection = Detection(
#                 engine_name=engine_name,
#                 engine_version=engine_result.get("engine_version"),
#                 method=engine_result.get("method"),
#                 category=category,
#                 result=result_str,
#                 file_hash=file_hash,
#                 malware_id=malware_obj.id
#             )
#             db.add(detection)
#             logger.info(f"Detection added: {engine_name} -> {result_str}")
#
#     await db.commit()
#
#     if malicious_found:
#         logger.warning(f"MALICIOUS CONTENT FOUND for app={application_id}, hash={file_hash}")
#     else:
#         logger.info(f"Scan result saved - No threats found for app={application_id}, hash={file_hash}")


# async def save_scan_result(report: dict, db: AsyncSession, application_id: str, file_hash: str):
#     """
#     Extract scan results and save to database.
#     """
#     attributes = report.get("data", {}).get("attributes", {})
#     results = attributes.get("last_analysis_results", {}) or attributes.get("results", {})
#     stats = attributes.get("last_analysis_stats", {})
#
#     # Find or create App
#     query = await db.execute(select(App).where(App.application_id == application_id))
#     app_obj = query.scalars().first()
#
#     if not app_obj:
#         app_obj = App(application_id=application_id, file_hash=file_hash)
#         db.add(app_obj)
#         logger.info(f"App created: {application_id} with hash: {file_hash}")
#     else:
#         # Update hash if not set
#         if not app_obj.file_hash:
#             app_obj.file_hash = file_hash
#
#     # Update scan statistics
#     app_obj.total_engines = stats.get("total", 0)
#     app_obj.malicious_count = stats.get("malicious", 0)
#     app_obj.suspicious_count = stats.get("suspicious", 0)
#     app_obj.harmless_count = stats.get("harmless", 0)
#     app_obj.undetected_count = stats.get("undetected", 0)
#
#     # Convert timestamp if available
#     if attributes.get("last_analysis_date"):
#         from datetime import datetime
#         app_obj.scan_date = datetime.fromtimestamp(attributes["last_analysis_date"])
#
#     # Process scan results
#     for engine_name, engine_result in results.items():
#         category = engine_result.get("category")
#         result_str = engine_result.get("result")
#
#         if category in ["malicious", "suspicious"] and result_str:
#             # Find or create Malware
#             malware_query = await db.execute(select(Malware).where(Malware.name == result_str))
#             malware_obj = malware_query.scalars().first()
#
#             if not malware_obj:
#                 malware_obj = Malware(name=result_str, category=category)
#                 db.add(malware_obj)
#                 await db.commit()
#                 await db.refresh(malware_obj)
#                 logger.info(f"Malware created: {result_str}")
#
#             # Link Malware to App if not linked
#             if malware_obj not in app_obj.malwares:
#                 app_obj.malwares.append(malware_obj)
#
#             # Create Detection record
#             detection = Detection(
#                 engine_name=engine_name,
#                 engine_version=engine_result.get("engine_version"),
#                 method=engine_result.get("method"),
#                 category=category,
#                 result=result_str,
#                 file_hash=file_hash,
#                 malware_id=malware_obj.id
#             )
#             db.add(detection)
#             logger.info(f"Detection added: {engine_name} -> {result_str}")
#
#     await db.commit()
#     logger.info(f"Scan result saved for app={application_id}, hash={file_hash}")


async def send_notification(device_code: str, report: dict):
    """
    Send POST request to device with scan results.
    """
    import httpx
    device_endpoint = f"https://example.com/device/{device_code}/notify"
    try:
        attributes = report.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        notification_data = {
            "scan_id": report.get("data", {}).get("id"),
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "total_engines": stats.get("total", 0),
            "scan_date": attributes.get("last_analysis_date"),
            "sha256": attributes.get("sha256"),
            "status": "completed"
        }

        async with httpx.AsyncClient() as client:
            await client.post(device_endpoint, json=notification_data)
        logger.info(f"Notification sent to device {device_code}")
    except Exception as e:
        logger.error(f"Failed to send notification to device {device_code}: {e}")


@router.get("/init")
async def init(db: db_dependency):
    try:
        result = await db.execute(select(App))
        apps = result.scalars().all()
        serializer = AppSerializer()
        logger.info(f"/init returned {len(apps)} apps")
        return {"apps": serializer.dump(apps, many=True)}
    except Exception as e:
        logger.exception(f"/init error: {e}")
        raise HTTPException(detail=str(e), status_code=status.HTTP_400_BAD_REQUEST)


async def scan_worker():
    """Background worker for processing pending tasks."""
    repo = VirusTotalRepository()

    while True:
        async with async_session_factory() as db:
            result = await db.execute(
                select(ScanTask).where(ScanTask.status.in_([ScanStatus.PENDING, ScanStatus.TIMEOUT]))
            )
            tasks = result.scalars().all()

            for task in tasks:
                # Skip if task is already being processed by another worker
                if task.status == ScanStatus.PROCESSING:
                    continue

                # Update status to processing
                task.status = ScanStatus.PROCESSING
                await db.commit()
                await db.refresh(task)

                try:
                    # Calculate hash if not set
                    if not task.scanning_hash and task.file_bytes:
                        task.scanning_hash = calculate_file_hash(task.file_bytes)
                        await db.commit()

                    # Step 1: Try to get existing report from VT using hash
                    if task.scanning_hash:
                        try:
                            # Add delay between VT API calls to avoid rate limiting
                            await asyncio.sleep(15)  # Wait 15 seconds between requests

                            report = await repo.get_file_report(task.scanning_hash)

                            if report:
                                # File exists in VT database - use existing report
                                logger.info(f"Using existing VT report for task {task.application_id}")
                                await save_scan_result(report, db, task.application_id, task.scanning_hash)
                                await send_notification(task.device_code, report)

                                # Mark task as completed and remove it
                                await db.delete(task)
                                await db.commit()
                                logger.info(f"Task {task.application_id} COMPLETED using existing VT report")
                                continue  # Move to next task

                        except aiohttp.ClientResponseError as e:
                            if e.status == 429:
                                # Rate limited - wait longer and keep task in processing
                                wait_time = 60  # Wait 1 minute
                                logger.warning(
                                    f"Rate limited on hash check for {task.application_id}, waiting {wait_time}s")
                                task.status = ScanStatus.PENDING  # Reset to pending for retry
                                await db.commit()
                                await asyncio.sleep(wait_time)
                                continue
                            else:
                                raise  # Re-raise other HTTP errors

                    # Step 2: If no existing report or no file bytes, upload file
                    if not task.file_bytes or len(task.file_bytes) == 0:
                        logger.warning(f"Task {task.id} has no file bytes, marking as failed")
                        task.status = ScanStatus.FAILED
                        await db.commit()
                        continue

                    # Upload file to VT with rate limiting
                    try:
                        # Add delay before upload
                        await asyncio.sleep(15)

                        vt_resp = await repo.scan_file(task.file_bytes, f"{task.application_id}.apk")
                        analysis_id = vt_resp.get("data", {}).get("id")

                        if not analysis_id:
                            task.status = ScanStatus.FAILED
                            await db.commit()
                            logger.warning(f"Task {task.application_id} FAILED (no analysis id)")
                            continue

                        # Step 3: Poll for scan completion with better rate limiting
                        logger.info(f"Polling for scan results: {analysis_id}")
                        for attempt in range(60):  # Reduced from 80 to 60 attempts
                            try:
                                # Add delay between poll requests
                                await asyncio.sleep(10)  # Wait 10 seconds between polls

                                report = await repo.get_analysis_report(analysis_id)
                                status_attr = report.get("data", {}).get("attributes", {}).get("status")

                                if status_attr == "completed":
                                    await save_scan_result(report, db, task.application_id, task.scanning_hash)
                                    await send_notification(task.device_code, report)
                                    await db.delete(task)
                                    await db.commit()
                                    logger.info(f"Task {task.application_id} COMPLETED after upload and scan")
                                    break

                                # Still processing
                                if attempt % 5 == 0:  # Log every 5 attempts
                                    logger.info(f"Scan still processing... attempt {attempt + 1}/60")

                            except aiohttp.ClientResponseError as e:
                                if e.status == 429:
                                    wait_time = 60  # Wait 1 minute for rate limit
                                    logger.warning(
                                        f"Rate limited during polling, waiting {wait_time}s... attempt {attempt + 1}/60")
                                    await asyncio.sleep(wait_time)
                                    continue
                                else:
                                    raise
                        else:
                            # If we get here, polling timed out
                            task.status = ScanStatus.TIMEOUT
                            await db.commit()
                            logger.warning(f"Task {task.application_id} TIMEOUT after polling")

                    except aiohttp.ClientResponseError as e:
                        if e.status == 429:
                            # Rate limited on upload - wait and retry later
                            wait_time = 60
                            logger.warning(f"Rate limited on upload for {task.application_id}, waiting {wait_time}s")
                            task.status = ScanStatus.PENDING
                            await db.commit()
                            await asyncio.sleep(wait_time)
                        else:
                            raise

                except Exception as e:
                    logger.exception(f"Unexpected error for task {task.application_id}: {e}")
                    task.status = ScanStatus.PENDING
                    await db.commit()
                    # Wait before retrying failed task
                    await asyncio.sleep(30)

        # Wait before checking for new tasks again
        await asyncio.sleep(30)  # Increased from 5 to 30 seconds


@router.on_event("startup")
async def start_worker():
    asyncio.create_task(scan_worker())
