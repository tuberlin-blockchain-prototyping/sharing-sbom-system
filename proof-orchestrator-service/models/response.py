from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class HealthResponse(BaseModel):
    status: str = Field(default="healthy")
    merkle_proof_service: str
    ipfs_service: str


class ProofGenerationResponse(BaseModel):
    status: str = Field(default="success")
    ipfs_cid: str
    tx_hash: str
    compliance_status: Optional[bool] = None
    root_hash: str
    composite_hash: str
    warning: Optional[str] = None
    proving_service_metrics: Optional[Dict[str, Any]] = None
