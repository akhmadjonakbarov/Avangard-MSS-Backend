# import asyncio
# from typing import Optional, Dict, Any
# import os
# import hashlib
#
# import aiohttp
# from tenacity import AsyncRetrying, stop_after_attempt, wait_exponential, retry_if_exception_type
#
# from core.exceptions import ScanTaskException
#
# API_BASE = os.getenv("VT_API_BASE", "https://www.virustotal.com/api/v3")
# API_KEY = os.getenv("VT_API_KEY")  # set your API key in env
# DEFAULT_TIMEOUT = 30.0
# MAX_CONCURRENT = int(os.getenv("VT_MAX_CONCURRENT", "3"))
# RETRIES = int(os.getenv("VT_RETRIES", "3"))
# VT_SIMPLE_UPLOAD_MAX = 32 * 1024 * 1024  # 32 MB
#
#
# class VirusTotalRepository:
#     def __init__(self, session: Optional[aiohttp.ClientSession] = None, api_key: Optional[str] = None):
#         self._external_session = session
#         self.api_key = api_key or API_KEY
#         self._semaphore = asyncio.Semaphore(MAX_CONCURRENT)
#
#     def _headers(self) -> Dict[str, str]:
#         if not self.api_key:
#             raise RuntimeError("API key not provided. Set VT_API_KEY env or pass api_key to constructor.")
#         return {
#             "x-apikey": self.api_key,
#             "Accept": "application/json",
#         }
#
#     async def _get_session(self) -> aiohttp.ClientSession:
#         if self._external_session:
#             return self._external_session
#         return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT))
#
#     async def scan_file(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
#         """
#         Upload and analyze a file using VirusTotal /files endpoint.
#         """
#         size = len(file_bytes)
#         async with self._semaphore:
#             if size <= VT_SIMPLE_UPLOAD_MAX:
#                 async for attempt in AsyncRetrying(
#                         stop=stop_after_attempt(RETRIES),
#                         wait=wait_exponential(multiplier=1, min=1, max=10),
#                         retry=retry_if_exception_type(aiohttp.ClientError),
#                         reraise=True,
#                 ):
#                     with attempt:
#                         session = await self._get_session()
#                         close_after = session is not self._external_session
#                         try:
#                             data = aiohttp.FormData()
#                             data.add_field(
#                                 "file",
#                                 file_bytes,
#                                 filename=filename,
#                                 content_type="application/octet-stream",
#                             )
#                             url = f"{API_BASE}/files"
#                             async with session.post(url, headers=self._headers(), data=data) as resp:
#                                 resp.raise_for_status()
#                                 return await resp.json()
#                         finally:
#                             if close_after:
#                                 await session.close()
#             else:
#                 raise ScanTaskException(message="File too large; please handle upload_url separately.", error_code=999)
#
#     # In repositories.py - REPLACE the get_file_report method with this:
#
#     async def get_file_report(self, file_hash: str) -> Dict[str, Any]:
#         """
#         Get existing scan report for a file using its SHA-256 hash.
#         """
#         session = await self._get_session()
#         close_after = session is not self._external_session
#         try:
#             url = f"{API_BASE}/files/{file_hash}"
#             async with session.get(url, headers=self._headers()) as resp:
#                 if resp.status == 404:
#                     return None
#                 resp.raise_for_status()
#                 return await resp.json()
#         finally:
#             if close_after:
#                 await session.close()
#
#     async def get_analysis_report(self, analysis_id: str) -> Dict[str, Any]:
#         """
#         Fetch file scan report using its analysis id.
#         """
#         async with self._semaphore:
#             async for attempt in AsyncRetrying(
#                     stop=stop_after_attempt(RETRIES),
#                     wait=wait_exponential(multiplier=2, min=5, max=60),
#                     retry=retry_if_exception_type(aiohttp.ClientResponseError),
#                     reraise=True,
#             ):
#                 with attempt:
#                     session = await self._get_session()
#                     close_after = session is not self._external_session
#                     try:
#                         url = f"{API_BASE}/analyses/{analysis_id}"
#                         async with session.get(url, headers=self._headers()) as resp:
#                             if resp.status == 429:
#                                 raise aiohttp.ClientResponseError(
#                                     resp.request_info, resp.history,
#                                     status=429, message="Too Many Requests", headers=resp.headers
#                                 )
#                             resp.raise_for_status()
#                             return await resp.json()
#                     finally:
#                         if close_after:
#                             await session.close()
#
#     @staticmethod
#     def calculate_file_hash(file_bytes: bytes) -> str:
#         """Calculate SHA-256 hash of file bytes."""
#         return hashlib.sha256(file_bytes).hexdigest()


import asyncio
from typing import Optional, Dict, Any, List
import os
import hashlib
import aiohttp
from tenacity import AsyncRetrying, stop_after_attempt, wait_exponential, retry_if_exception_type
from core.exceptions import ScanTaskException

API_BASE = os.getenv("VT_API_BASE", "https://www.virustotal.com/api/v3")
DEFAULT_TIMEOUT = 30.0
MAX_CONCURRENT = int(os.getenv("VT_MAX_CONCURRENT", "3"))
RETRIES = int(os.getenv("VT_RETRIES", "3"))
VT_SIMPLE_UPLOAD_MAX = 32 * 1024 * 1024  # 32 MB

# Collect API keys from environment
API_KEYS = [
    os.getenv("VT_API_KEY"),
    os.getenv("VT_API_KEY2"),
    os.getenv("VT_API_KEY3"),
    os.getenv("VT_API_KEY4"),
]

class VirusTotalRepository:
    def __init__(self, session: Optional[aiohttp.ClientSession] = None, api_keys: Optional[List[str]] = None):
        self._external_session = session
        self.api_keys = api_keys or [k for k in API_KEYS if k]
        if not self.api_keys:
            raise RuntimeError("No API keys provided for VirusTotalRepository.")
        self.key_index = 0
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    def _current_key(self) -> str:
        return self.api_keys[self.key_index]

    def _rotate_key(self):
        self.key_index = (self.key_index + 1) % len(self.api_keys)

    def _headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self._current_key(),
            "Accept": "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._external_session:
            return self._external_session
        return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT))

    async def _request_with_rotation(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Make a VT request and rotate API key if 429 received.
        """
        for attempt in range(len(self.api_keys)):
            session = await self._get_session()
            close_after = session is not self._external_session
            try:
                async with session.request(method, url, headers=self._headers(), **kwargs) as resp:
                    if resp.status == 429:
                        print(f"API key {self._current_key()} rate-limited, rotating key...")
                        self._rotate_key()
                        await asyncio.sleep(1)  # small delay before retry
                        continue
                    if resp.status == 404:
                        return None
                    resp.raise_for_status()
                    return await resp.json()
            finally:
                if close_after:
                    await session.close()
        raise RuntimeError("All API keys are rate-limited or exhausted")

    async def scan_file(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Upload and analyze a file using VirusTotal /files endpoint.
        """
        size = len(file_bytes)
        async with self._semaphore:
            if size > VT_SIMPLE_UPLOAD_MAX:
                raise ScanTaskException(message="File too large; please handle upload_url separately.", error_code=999)

            data = aiohttp.FormData()
            data.add_field("file", file_bytes, filename=filename, content_type="application/octet-stream")
            url = f"{API_BASE}/files"
            return await self._request_with_rotation("POST", url, data=data)

    async def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get existing scan report for a file using its SHA-256 hash.
        """
        url = f"{API_BASE}/files/{file_hash}"
        return await self._request_with_rotation("GET", url)

    async def get_analysis_report(self, analysis_id: str) -> Dict[str, Any]:
        """
        Fetch file scan report using its analysis id.
        """
        url = f"{API_BASE}/analyses/{analysis_id}"
        return await self._request_with_rotation("GET", url)

    @staticmethod
    def calculate_file_hash(file_bytes: bytes) -> str:
        """Calculate SHA-256 hash of file bytes."""
        return hashlib.sha256(file_bytes).hexdigest()
