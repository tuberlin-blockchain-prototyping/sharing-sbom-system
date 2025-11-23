import re

def normalize_root_hash(root_hash: str) -> str:
    """Normalize root hash: lowercase, remove 0x prefix."""
    if not root_hash:
        raise ValueError("Root hash cannot be empty")
    
    normalized = root_hash.lower().strip()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    
    if not re.match(r"^[0-9a-f]{64}$", normalized):
        raise ValueError("Invalid root hash format (expected 64 hex characters)")
    
    return normalized

