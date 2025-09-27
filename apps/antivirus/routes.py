# In device_routes.py - FIX the status access and move serializers:

import asyncio
import hashlib
import logging
import time  # Add this import

from sqlalchemy import delete
from datetime import datetime
import aiohttp
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database_config import async_session_factory
from di.db import db_dependency
from di.device import device_dependency
from .models import App, Malware, ScanTask, ScanStatus, Detection, app_malware
from .repositories import VirusTotalRepository
from .serializers import AppSerializer, ScanTaskSerializer  # Import from serializers

router = APIRouter()

# Configure logging
logger = logging.getLogger("antivirus")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


# VirusTotal rate limiting tracker
class VTRateLimiter:
    def __init__(self):
        self.last_request_time = 0
        self.requests_this_minute = 0
        self.minute_start_time = time.time()

    async def wait_if_needed(self):
        current_time = time.time()

        # Reset counter if we're in a new minute
        if current_time - self.minute_start_time >= 60:
            self.requests_this_minute = 0
            self.minute_start_time = current_time

        # If we've made 4 requests this minute, wait until next minute
        if self.requests_this_minute >= 4:
            wait_time = 60 - (current_time - self.minute_start_time)
            if wait_time > 0:
                logger.info(f"Rate limit reached. Waiting {wait_time:.1f} seconds")
                await asyncio.sleep(wait_time)
                self.requests_this_minute = 0
                self.minute_start_time = time.time()

        # Ensure at least 15 seconds between requests
        time_since_last = current_time - self.last_request_time
        if time_since_last < 15:
            await asyncio.sleep(15 - time_since_last)

        self.requests_this_minute += 1
        self.last_request_time = time.time()


# Global rate limiter
vt_rate_limiter = VTRateLimiter()


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

    # Create new scan task
    new_task = ScanTask(
        application_id=application_id,
        file_bytes=file_bytes,
        scanning_hash=file_hash,
        status=ScanStatus.PENDING.value,  # ADD .value here
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
        existing_task: ScanTask = (await db.execute(task_query)).scalars().first()

        if existing_task:
            if existing_task.status == ScanStatus.FAILED.value:
                existing_task.status = ScanStatus.PENDING.value
                await  db.commit()
                logger.info(f"Scan task status updated: {ScanStatus.PENDING.value}")

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
            status=ScanStatus.PENDING.value,
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
    Overwrites previous results if the same application_id has a different file_hash.
    """
    attributes = report.get("data", {}).get("attributes", {})
    results = attributes.get("last_analysis_results", {}) or attributes.get("results", {})
    stats = attributes.get("last_analysis_stats", {})

    # Find existing app
    query = await db.execute(select(App).where(App.application_id == application_id))
    app_obj = query.scalars().first()

    if app_obj:
        # If file hash changed, remove old results
        if app_obj.file_hash != file_hash:
            logger.info(f"App {application_id} has new file hash. Removing old detections and malware links.")

            # Delete old detections
            await db.execute(delete(Detection).where(Detection.file_hash == app_obj.file_hash))

            # Clear malware links in association table
            from .models import app_malware
            await db.execute(app_malware.delete().where(app_malware.c.app_id == app_obj.id))

            # Update file hash
            app_obj.file_hash = file_hash
            await db.commit()
            await db.refresh(app_obj)
    else:
        # Create new App
        app_obj = App(application_id=application_id, file_hash=file_hash)
        db.add(app_obj)
        await db.commit()
        await db.refresh(app_obj)
        logger.info(f"App created: {application_id} with hash: {file_hash}")

    # Update scan statistics
    app_obj.total_engines = stats.get("total", 0)
    app_obj.malicious_count = stats.get("malicious", 0)
    app_obj.suspicious_count = stats.get("suspicious", 0)
    app_obj.harmless_count = stats.get("harmless", 0)
    app_obj.undetected_count = stats.get("undetected", 0)
    if attributes.get("last_analysis_date"):
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

            # Link malware to app
            if malware_obj not in app_obj.malwares:
                app_obj.malwares.append(malware_obj)
                logger.info(f"Linked malware {result_str} to app {application_id}")

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
async def init(
        db: db_dependency,
        # device: device_dependency
):
    try:
        result = await db.execute(select(App))
        apps = result.scalars().all()
        serializer = AppSerializer()
        logger.info(f"/init returned {len(apps)} apps")

        return {
            "apps": serializer.dump(apps, many=True)
        }
    except Exception as e:
        logger.exception(f"/init error: {e}")
        raise HTTPException(detail=str(e), status_code=status.HTTP_400_BAD_REQUEST)


async def scan_worker():
    """Background worker for processing pending tasks with proper rate limiting."""
    repo = VirusTotalRepository()

    while True:
        async with async_session_factory() as db:
            # Get only 2 tasks at a time to respect rate limits
            result = await db.execute(
                select(ScanTask)
                .where(
                    ScanTask.status.in_([ScanStatus.PENDING.value, ScanStatus.TIMEOUT.value, ScanStatus.FAILED.value]))
                .order_by(ScanTask.created_at.asc())
                .limit(2)
            )
            tasks = result.scalars().all()

            for task in tasks:
                application_id = task.application_id
                result_one = await db.execute(
                    select(App).where(App.application_id == application_id)
                )
                existed_task = result_one.scalar_one_or_none()
                if existed_task:
                    await db.delete(existed_task)
                    continue

                if task.status == ScanStatus.PROCESSING.value:
                    continue

                task.status = ScanStatus.PROCESSING.value
                await db.commit()
                await db.refresh(task)

                try:
                    # Calculate hash if not set
                    if not task.scanning_hash and task.file_bytes:
                        task.scanning_hash = calculate_file_hash(task.file_bytes)
                        await db.commit()

                    # Step 1: Check VT for existing report
                    if task.scanning_hash:
                        try:
                            await vt_rate_limiter.wait_if_needed()
                            report = await repo.get_file_report(task.scanning_hash)

                            if report:
                                logger.info(f"Using existing VT report for {task.application_id}")
                                await save_scan_result(report, db, task.application_id, task.scanning_hash)
                                await send_notification(task.device_code, report)
                                await db.delete(task)
                                await db.commit()
                                logger.info(f"Task {task.application_id} COMPLETED using existing report")
                                continue
                        except RuntimeError as e:
                            logger.warning(f"VT API keys exhausted: {e}. Will retry task later.")
                            task.status = ScanStatus.PENDING.value  # Reset to pending to retry later
                            await db.commit()
                            await asyncio.sleep(60)  # Wait 1 minute before next task
                            continue

                        except aiohttp.ClientResponseError as e:
                            if e.status == 429:
                                logger.warning(f"Rate limited on hash check for {task.application_id}")
                                task.status = ScanStatus.PENDING.value
                                await db.commit()
                                await asyncio.sleep(60)
                                break
                            else:
                                raise

                    # Step 2: Upload file if needed
                    if not task.file_bytes or len(task.file_bytes) == 0:
                        logger.warning(f"Task {task.id} has no file bytes")
                        task.status = ScanStatus.FAILED.value
                        await db.commit()
                        continue

                    try:
                        await vt_rate_limiter.wait_if_needed()
                        vt_resp = await repo.scan_file(task.file_bytes, f"{task.application_id}.apk")
                        analysis_id = vt_resp.get("data", {}).get("id")

                        if not analysis_id:
                            task.status = ScanStatus.FAILED.value
                            await db.commit()
                            continue

                        # Step 3: Poll for results
                        logger.info(f"Polling for scan results: {analysis_id}")
                        for attempt in range(12):  # 12 attempts = 6 minutes max
                            try:
                                await asyncio.sleep(30)  # Wait 30 seconds between polls
                                await vt_rate_limiter.wait_if_needed()
                                report = await repo.get_analysis_report(analysis_id)
                                status_attr = report.get("data", {}).get("attributes", {}).get("status")

                                if status_attr == "completed":
                                    await save_scan_result(report, db, task.application_id, task.scanning_hash)
                                    await send_notification(task.device_code, report)
                                    await db.delete(task)
                                    await db.commit()
                                    logger.info(f"Task {task.application_id} COMPLETED after scan")
                                    break

                                logger.info(f"Scan processing... attempt {attempt + 1}/12")

                            except aiohttp.ClientResponseError as e:
                                if e.status == 429:
                                    logger.warning(f"Rate limited during polling, waiting 60s")
                                    await asyncio.sleep(60)
                                    continue
                                else:
                                    raise
                        else:
                            task.status = ScanStatus.TIMEOUT.value
                            await db.commit()
                            logger.warning(f"Task {task.application_id} TIMEOUT after 6 minutes")

                    except aiohttp.ClientResponseError as e:
                        if e.status == 429:
                            logger.warning(f"Rate limited on upload for {task.application_id}")
                            task.status = ScanStatus.PENDING.value
                            await db.commit()
                            await asyncio.sleep(60)
                            break
                        else:
                            raise

                except Exception as e:
                    logger.exception(f"Unexpected error for task {task.application_id}: {e}")
                    task.status = ScanStatus.PENDING.value
                    await db.commit()
                    await asyncio.sleep(30)

        await asyncio.sleep(30)


@router.on_event("startup")
async def start_worker():
    asyncio.create_task(scan_worker())
