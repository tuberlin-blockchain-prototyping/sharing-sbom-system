import os
from pathlib import Path

class Config:
    IPFS_HOST = os.getenv("IPFS_HOST", "localhost")
    IPFS_PORT = int(os.getenv("IPFS_PORT", "5001"))
    IPFS_PROTOCOL = os.getenv("IPFS_PROTOCOL", "http")
    
    DB_PATH = os.getenv("DB_PATH", "/data/ipfs.db")
    DB_DIR = Path(DB_PATH).parent
    DB_DIR.mkdir(parents=True, exist_ok=True)
    
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

