from fastapi import APIRouter
from models.response import HealthResponse
from service.merkle_client import MerkleClient
from service.ipfs_client import IPFSClient

router = APIRouter(prefix="/health", tags=["health"])

@router.get("", response_model=HealthResponse)
async def health_check():
    merkle_client = MerkleClient()
    ipfs_client = IPFSClient()
    
    merkle_status = "healthy" if await merkle_client.health_check() else "unhealthy"
    ipfs_status = "healthy" if await ipfs_client.health_check() else "unhealthy"
    
    return HealthResponse(
        status="healthy",
        merkle_proof_service=merkle_status,
        ipfs_service=ipfs_status
    )

