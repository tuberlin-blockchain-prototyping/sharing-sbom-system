import os

class Config:
    PORT: int = int(os.getenv("PORT", "8080"))
    HOST: str = os.getenv("HOST", "0.0.0.0")
    
    MERKLE_PROOF_SERVICE_URL: str = os.getenv(
        "MERKLE_PROOF_SERVICE_URL",
        "http://merkle-proof-service.sharing-sbom-system.svc.cluster.local:8090"
    )
    PROVING_SERVICE_URL: str = os.getenv(
        "PROVING_SERVICE_URL",
        "http://proving-service.sharing-sbom-system.svc.cluster.local:8080"
    )
    IPFS_SERVICE_URL: str = os.getenv(
        "IPFS_SERVICE_URL",
        "http://ipfs-service.sharing-sbom-system.svc.cluster.local:80"
    )
    
    BLOCKCHAIN_CONTRACT_ADDRESS: str = os.getenv(
        "BLOCKCHAIN_CONTRACT_ADDRESS",
        "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    )
    BLOCKCHAIN_NAMESPACE: str = os.getenv("BLOCKCHAIN_NAMESPACE", "blockchain")
    BLOCKCHAIN_SCRIPT_PATH: str = os.getenv(
        "BLOCKCHAIN_SCRIPT_PATH",
        "/workspace/store_merkle_proof.js"
    )
    
    MERKLE_PROOF_TIMEOUT: int = int(os.getenv("MERKLE_PROOF_TIMEOUT", "1800"))
    PROVING_TIMEOUT: int = int(os.getenv("PROVING_TIMEOUT", "1800"))
    IPFS_TIMEOUT: int = int(os.getenv("IPFS_TIMEOUT", "300"))
    BLOCKCHAIN_TIMEOUT: int = int(os.getenv("BLOCKCHAIN_TIMEOUT", "300"))

