import logging
from typing import Dict, Any
from .merkle_client import MerkleClient
from .ipfs_client import IPFSClient
from .blockchain_client import BlockchainClient

logger = logging.getLogger(__name__)

class ProofService:
    def __init__(self):
        self.merkle_client = MerkleClient()
        self.ipfs_client = IPFSClient()
        self.blockchain_client = BlockchainClient()
    
    async def generate_and_store_proof(self, root_hash: str, banned_list: list) -> Dict[str, Any]:
        logger.info(f"Starting proof generation for root_hash={root_hash}")
        
        proof_response = await self.merkle_client.generate_proofs(root_hash, banned_list)
        
        banned_list_hash = proof_response.get("banned_list_hash")
        compliant = proof_response.get("compliant", False)
        proof_root_hash = proof_response.get("root_hash") or proof_response.get("proof", {}).get("root_hash") or root_hash
        
        if not banned_list_hash:
            raise ValueError("banned_list_hash not found in proof response")
        
        logger.info(f"Extracted: banned_list_hash={banned_list_hash[:16]}..., compliant={compliant}")
        
        ipfs_cid = await self.ipfs_client.store_proof(proof_response, proof_root_hash)
        
        tx_hash = await self.blockchain_client.store_merkle_proof(
            root_hash=proof_root_hash,
            ipfs_cid=ipfs_cid,
            banned_list_hash=banned_list_hash,
            compliant=compliant
        )
        
        logger.info(f"Proof generation completed: tx_hash={tx_hash}")
        
        return {
            "ipfs_cid": ipfs_cid,
            "tx_hash": tx_hash,
            "compliance_status": compliant,
            "root_hash": proof_root_hash
        }

