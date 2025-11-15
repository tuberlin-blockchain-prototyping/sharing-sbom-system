import re

def normalize_sbom_hash(sbom_hash: str) -> str:
    """Normalize SBOM hash: lowercase, remove 0x prefix."""
    if not sbom_hash:
        raise ValueError("SBOM hash cannot be empty")
    
    normalized = sbom_hash.lower().strip()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    
    if not re.match(r"^[0-9a-f]{64}$", normalized):
        raise ValueError("Invalid SBOM hash format (expected 64 hex characters)")
    
    return normalized

