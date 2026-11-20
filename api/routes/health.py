from fastapi import APIRouter

from schemas import HealthCheck
from config import settings

router = APIRouter()


@router.get("/", response_model=HealthCheck)
async def health_check():
    return HealthCheck(status="healthy", version=settings.version)
