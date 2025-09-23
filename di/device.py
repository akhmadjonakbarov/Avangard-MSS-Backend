from typing import Annotated
from fastapi import Depends

from apps.devices.utils.device_manager import get_current_device

device_dependency = Annotated[dict, Depends(get_current_device)]
