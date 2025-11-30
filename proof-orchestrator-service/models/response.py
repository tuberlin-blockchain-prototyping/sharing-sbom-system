from pydantic import BaseModel, Field

class HealthResponse(BaseModel):
    status: str = Field(default="healthy")
    merkle_proof_service: str
    ipfs_service: str

class ProofGenerationResponse(BaseModel):
    status: str = Field(default="success")
    ipfs_cid: str
    tx_hash: str
    compliance_status: bool
    root_hash: str
    composite_hash: str

