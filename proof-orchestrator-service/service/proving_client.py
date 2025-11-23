import httpx
import logging
from typing import Dict, Any, List
from config import Config

logger = logging.getLogger(__name__)

class ProvingClient:
    def __init__(self, base_url: str = None):
        self.base_url = base_url or Config.PROVING_SERVICE_URL
        self.timeout = Config.PROVING_TIMEOUT
    
    async def prove_merkle_compact(self, root: str, depth: int, merkle_proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
        url = f"{self.base_url}/prove-merkle-compact"
        
        payload = {
            "root": root,
            "depth": depth,
            "merkle_proofs": merkle_proofs
        }
        
        logger.info(f"Calling proving-service: {url}")
        logger.debug(f"Request payload: root={root}, depth={depth}, proofs_count={len(merkle_proofs)}")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                result = response.json()
                logger.info(f"Received proof response from proving-service")
                return result
            except httpx.HTTPStatusError as e:
                logger.error(f"Proving-service error: {e.response.status_code} - {e.response.text}")
                raise Exception(f"Proving-service error: {e.response.status_code}")
            except httpx.RequestError as e:
                logger.error(f"Failed to connect to proving-service: {e}")
                raise Exception(f"Failed to connect to proving-service: {str(e)}")
    
    async def health_check(self) -> bool:
        url = f"{self.base_url}/health"
        
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(url)
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Proving-service health check failed: {e}")
            return False

