from fastapi import APIRouter, HTTPException
import logging
from models.request import ProofGenerationRequest
from models.response import ProofGenerationResponse
from service.proof_service import ProofService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/generate-proof", tags=["proof"])

@router.post("", response_model=ProofGenerationResponse)
async def generate_proof(request: ProofGenerationRequest):
    try:
        proof_service = ProofService()
        result = await proof_service.generate_and_store_proof(
            root_hash=request.root_hash,
            banned_list=request.banned_list
        )
        
        return ProofGenerationResponse(
            status="success",
            ipfs_cid=result["ipfs_cid"],
            tx_hash=result["tx_hash"],
            compliance_status=result["compliance_status"],
            root_hash=result["root_hash"]
        )
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Proof generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

