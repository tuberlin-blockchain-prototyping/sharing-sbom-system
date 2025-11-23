import httpx
import logging
from typing import Dict, Any
from config import Config

logger = logging.getLogger(__name__)

class MerkleClient:
    def __init__(self, base_url: str = None):
        self.base_url = base_url or Config.MERKLE_PROOF_SERVICE_URL
        self.timeout = Config.MERKLE_PROOF_TIMEOUT
    
    async def generate_proofs(self, root_hash: str, banned_list: list) -> Dict[str, Any]:
        url = f"{self.base_url}/prove-batch"
        
        payload = {
            "root": root_hash,
            "purls": banned_list,
            "compress": True,
            "accumulator": "smt"
        }
        
        logger.info(f"Calling merkle-proof-service: {url}")
        logger.debug(f"Request payload: root={root_hash}, purls_count={len(banned_list)}")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                result = response.json()
                logger.info(f"Received proof response from merkle-proof-service")
                return result
            except httpx.HTTPStatusError as e:
                logger.error(f"Merkle-proof-service error: {e.response.status_code} - {e.response.text}")
                raise Exception(f"Merkle-proof-service error: {e.response.status_code}")
            except httpx.RequestError as e:
                logger.error(f"Failed to connect to merkle-proof-service: {e}")
                raise Exception(f"Failed to connect to merkle-proof-service: {str(e)}")
    
    async def health_check(self) -> bool:
        url = f"{self.base_url}/health"
        
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(url)
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Merkle-proof-service health check failed: {e}")
            return False

