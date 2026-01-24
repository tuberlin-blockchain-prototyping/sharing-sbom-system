import hashlib
import json
import logging
import re
from typing import Dict, Any, Optional
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
        raise ValueError(
            f"Invalid hash format (expected 64 hex characters): {hash_str}"
        )
    return normalized


def compute_banned_list_hash(banned_list: list) -> str:
    """Compute banned_list_hash from banned_list (matches Rust implementation)."""
    # Use compact JSON format without spaces (matching serde_json::to_string in Rust)
    banned_list_json = json.dumps(banned_list, separators=(",", ":"))
    banned_list_bytes = banned_list_json.encode("utf-8")
    banned_list_hash = hashlib.sha256(banned_list_bytes).hexdigest()
    return banned_list_hash


def compute_composite_hash(root_hash: str, banned_list_hash: str) -> str:
    """Compute composite hash from root_hash and banned_list_hash."""
    normalized_root = _normalize_hash(root_hash)
    normalized_banned = _normalize_hash(banned_list_hash)
    concatenated = normalized_root + normalized_banned
    composite = hashlib.sha256(concatenated.encode("utf-8")).hexdigest()
    return composite


class ProofService:
    def __init__(self):
        self.merkle_client = MerkleClient()
        self.proving_client = ProvingClient()
        self.ipfs_client = IPFSClient()
        self.blockchain_client = BlockchainClient()

    async def generate_and_store_proof(
        self, root_hash: str, banned_list: list
    ) -> Dict[str, Any]:
        logger.info(f"Starting proof generation for root_hash={root_hash}")

        banned_list_hash = compute_banned_list_hash(banned_list)
        logger.info(f"Computed banned_list_hash={banned_list_hash[:16]}...")

        normalized_root = _normalize_hash(root_hash)
        composite_hash = compute_composite_hash(
            normalized_root, banned_list_hash)
        logger.info(f"Computed composite_hash={composite_hash[:16]}...")

        existing_proof = await self.ipfs_client.check_proof_exists(composite_hash)
        if existing_proof:
            logger.warning(
                f"Proof already exists in IPFS for composite_hash={composite_hash[:16]}... (ipfs_cid={existing_proof})"
            )
            return {
                "ipfs_cid": existing_proof,
                "tx_hash": "SKIPPED",
                "compliance_status": None,
                "root_hash": normalized_root,
                "composite_hash": composite_hash,
                "warning": "Proof already exists in IPFS. No new proof was generated.",
            }

        merkle_response = await self.merkle_client.generate_proofs(
            root_hash, banned_list
        )

        merkle_proofs = merkle_response.get("merkle_proofs", [])
        depth = merkle_response.get("depth", 256)
        root = merkle_response.get("root", root_hash)

        if not merkle_proofs:
            raise ValueError("No merkle proofs generated")

        logger.info(
            f"Got {len(merkle_proofs)} merkle proofs, calling proving-service")

        proving_response = await self.proving_client.prove_merkle_compact(
            root=root, depth=depth, merkle_proofs=merkle_proofs
        )

        proven_banned_list_hash = proving_response.get("banned_list_hash")
        compliant = proving_response.get("compliant", False)
        proof_root_hash_raw = proving_response.get("root_hash", root_hash)
        proof_root_hash = _normalize_hash(proof_root_hash_raw)

        if not proven_banned_list_hash:
            raise ValueError(
                "banned_list_hash not found in proving-service response")

        if proven_banned_list_hash.lower() != banned_list_hash.lower():
            raise ValueError(
                f"Banned list hash mismatch: computed={banned_list_hash}, proven={proven_banned_list_hash}"
            )

        logger.info(
            f"Extracted: banned_list_hash={proven_banned_list_hash[:16]}..., compliant={compliant}"
        )

        proven_composite_hash = compute_composite_hash(
            proof_root_hash, proven_banned_list_hash
        )
        if proven_composite_hash != composite_hash:
            raise ValueError(
                f"Composite hash mismatch: computed={composite_hash}, proven={proven_composite_hash}"
            )

        logger.info(f"Verified composite_hash={composite_hash[:16]}...")

        ipfs_cid = await self.ipfs_client.store_proof(proving_response, composite_hash)

        tx_hash = await self.blockchain_client.store_merkle_proof(
            root_hash=proof_root_hash,
            ipfs_cid=ipfs_cid,
            banned_list_hash=banned_list_hash,
            compliant=compliant,
        )

        if tx_hash == "SKIPPED":
            logger.info(
                "Proof already exists on blockchain for this root_hash + banned_list_hash combination"
            )
        else:
            logger.info(f"Proof generation completed: tx_hash={tx_hash}")

        return {
            "ipfs_cid": ipfs_cid,
            "tx_hash": tx_hash,
            "compliance_status": compliant,
            "root_hash": proof_root_hash,
            "composite_hash": composite_hash,
        }
