# vt_repository_file_only.py
import asyncio
from typing import Optional, Dict, Any
import os

import aiohttp
from tenacity import AsyncRetrying, stop_after_attempt, wait_exponential, retry_if_exception_type

API_BASE = os.getenv("VT_API_BASE", "https://www.virustotal.com/api/v3")
API_KEY = os.getenv("VT_API_KEY")  # set your API key in env
DEFAULT_TIMEOUT = 30.0
MAX_CONCURRENT = int(os.getenv("VT_MAX_CONCURRENT", "3"))
RETRIES = int(os.getenv("VT_RETRIES", "3"))
VT_SIMPLE_UPLOAD_MAX = 32 * 1024 * 1024  # 32 MB


class VirusTotalRepository:
    def __init__(self, session: Optional[aiohttp.ClientSession] = None, api_key: Optional[str] = None):
        self._external_session = session
        self.api_key = api_key or API_KEY
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise RuntimeError("API key not provided. Set VT_API_KEY env or pass api_key to constructor.")
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._external_session:
            return self._external_session
        return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT))

    async def scan_file(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Upload and analyze a file using VirusTotal /files endpoint.
        """
        size = len(file_bytes)
        async with self._semaphore:
            if size <= VT_SIMPLE_UPLOAD_MAX:
                async for attempt in AsyncRetrying(
                        stop=stop_after_attempt(RETRIES),
                        wait=wait_exponential(multiplier=1, min=1, max=10),
                        retry=retry_if_exception_type(aiohttp.ClientError),
                        reraise=True,
                ):
                    with attempt:
                        session = await self._get_session()
                        close_after = session is not self._external_session
                        try:
                            data = aiohttp.FormData()
                            data.add_field(
                                "file",
                                file_bytes,
                                filename=filename,
                                content_type="application/octet-stream",
                            )
                            url = f"{API_BASE}/files"
                            async with session.post(url, headers=self._headers(), data=data) as resp:
                                resp.raise_for_status()
                                return await resp.json()
                        finally:
                            if close_after:
                                await session.close()
            else:
                # For files >32MB, handle large file upload if needed
                raise RuntimeError("File too large; please handle upload_url separately.")

    async def get_report(self, resource: str) -> Dict[str, Any]:
        """
        Fetch file scan report using its analysis id.
        Retry automatically on 429 with backoff.
        """
        async with self._semaphore:
            async for attempt in AsyncRetrying(
                    stop=stop_after_attempt(RETRIES),
                    wait=wait_exponential(multiplier=2, min=5, max=60),
                    retry=retry_if_exception_type(aiohttp.ClientResponseError),
                    reraise=True,
            ):
                with attempt:
                    session = await self._get_session()
                    close_after = session is not self._external_session
                    try:
                        url = f"{API_BASE}/analyses/{resource}"
                        async with session.get(url, headers=self._headers()) as resp:
                            if resp.status == 429:
                                # Explicitly raise for Tenacity to retry
                                raise aiohttp.ClientResponseError(
                                    resp.request_info, resp.history,
                                    status=429, message="Too Many Requests", headers=resp.headers
                                )
                            resp.raise_for_status()
                            return await resp.json()
                    finally:
                        if close_after:
                            await session.close()
