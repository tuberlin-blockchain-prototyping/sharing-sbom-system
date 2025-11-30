import hashlib
import logging
import re
from typing import Dict, Any
from .merkle_client import MerkleClient
from .proving_client import ProvingClient
from .ipfs_client import IPFSClient
from .blockchain_client import BlockchainClient

logger = logging.getLogger(__name__)

def _normalize_hash(hash_str: str) -> str:
    """Normalize hash: lowercase, remove 0x prefix."""
    normalized = hash_str.lower().strip()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if not re.match(r"^[0-9a-f]{64}$", normalized):
        raise ValueError(f"Invalid hash format (expected 64 hex characters): {hash_str}")
    return normalized

def compute_composite_hash(root_hash: str, banned_list_hash: str) -> str:
    """Compute composite hash from root_hash and banned_list_hash."""
    normalized_root = _normalize_hash(root_hash)
    normalized_banned = _normalize_hash(banned_list_hash)
    concatenated = normalized_root + normalized_banned
    composite = hashlib.sha256(concatenated.encode('utf-8')).hexdigest()
    return composite

class ProofService:
    def __init__(self):
        self.merkle_client = MerkleClient()
        self.proving_client = ProvingClient()
        self.ipfs_client = IPFSClient()
        self.blockchain_client = BlockchainClient()
    
    async def generate_and_store_proof(self, root_hash: str, banned_list: list) -> Dict[str, Any]:
        logger.info(f"Starting proof generation for root_hash={root_hash}")
        
        merkle_response = await self.merkle_client.generate_proofs(root_hash, banned_list)
        
        merkle_proofs = merkle_response.get("merkle_proofs", [])
        depth = merkle_response.get("depth", 256)
        root = merkle_response.get("root", root_hash)
        
        if not merkle_proofs:
            raise ValueError("No merkle proofs generated")
        
        logger.info(f"Got {len(merkle_proofs)} merkle proofs, calling proving-service")
        
        proving_response = await self.proving_client.prove_merkle_compact(
            root=root,
            depth=depth,
            merkle_proofs=merkle_proofs
        )
        
        banned_list_hash = proving_response.get("banned_list_hash")
        compliant = proving_response.get("compliant", False)
        proof_root_hash = proving_response.get("root_hash", root_hash)
        
        if not banned_list_hash:
            raise ValueError("banned_list_hash not found in proving-service response")
        
        logger.info(f"Extracted: banned_list_hash={banned_list_hash[:16]}..., compliant={compliant}")
        
        composite_hash = compute_composite_hash(proof_root_hash, banned_list_hash)
        logger.info(f"Computed composite_hash={composite_hash[:16]}...")
        
        ipfs_cid = await self.ipfs_client.store_proof(proving_response, composite_hash)
        
        tx_hash = await self.blockchain_client.store_merkle_proof(
            root_hash=proof_root_hash,
            ipfs_cid=ipfs_cid,
            banned_list_hash=banned_list_hash,
            compliant=compliant
        )
        
        if tx_hash == "SKIPPED":
            logger.info("Proof already exists on blockchain for this root_hash + banned_list_hash combination")
        else:
            logger.info(f"Proof generation completed: tx_hash={tx_hash}")
        
        return {
            "ipfs_cid": ipfs_cid,
            "tx_hash": tx_hash,
            "compliance_status": compliant,
            "root_hash": proof_root_hash,
            "composite_hash": composite_hash
        }

