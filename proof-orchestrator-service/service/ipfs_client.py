import httpx
import json
import logging
from typing import Dict, Any
from config import Config

logger = logging.getLogger(__name__)


class IPFSClient:
    def __init__(self, base_url: str = None):
        self.base_url = base_url or Config.IPFS_SERVICE_URL
        self.timeout = Config.IPFS_TIMEOUT

    async def store_proof(self, proof_data: Dict[str, Any], composite_hash: str) -> str:
        url = f"{self.base_url}/store"

        import base64

        proof_json_str = json.dumps(proof_data)
        proof_bytes = proof_json_str.encode("utf-8")
        proof_base64 = base64.b64encode(proof_bytes).decode("utf-8")

        payload = {"proof": proof_base64, "composite_hash": composite_hash}

        logger.info(f"Storing proof on IPFS via ipfs-service: {url}")
        logger.debug(f"Proof size: {len(proof_bytes)} bytes")

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                result = response.json()
                ipfs_cid = result.get("ipfs_cid")

                if not ipfs_cid:
                    raise Exception("IPFS service did not return CID")

                logger.info(f"Proof stored on IPFS with CID: {ipfs_cid}")
                return ipfs_cid
            except httpx.HTTPStatusError as e:
                logger.error(
                    f"IPFS-service error: {e.response.status_code} - {e.response.text}"
                )
                raise Exception(f"IPFS-service error: {e.response.status_code}")
            except httpx.RequestError as e:
                logger.error(f"Failed to connect to ipfs-service: {e}")
                raise Exception(f"Failed to connect to ipfs-service: {str(e)}")

    async def health_check(self) -> bool:
        url = f"{self.base_url}/health"

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(url)
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"IPFS-service health check failed: {e}")
            return False
