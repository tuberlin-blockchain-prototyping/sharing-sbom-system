import os
import logging
from ipfshttpclient import Client
from config import Config

logger = logging.getLogger(__name__)

class IPFSClient:
    def __init__(self):
        self.client = None
        self._connect()
    
    def _connect(self):
        try:
            addr = f"/{Config.IPFS_PROTOCOL}/{Config.IPFS_HOST}:{Config.IPFS_PORT}"
            self.client = Client(addr=addr)
            self.client.id()
            logger.info(f"Connected to IPFS at {Config.IPFS_PROTOCOL}://{Config.IPFS_HOST}:{Config.IPFS_PORT}")
        except Exception as e:
            logger.error(f"Failed to connect to IPFS: {e}")
            logger.warning("IPFS service will run in mock mode")
            self.client = None
    
    def is_connected(self):
        return self.client is not None
    
    def add_bytes(self, data: bytes) -> str:
        if self.client is None:
            raise RuntimeError("IPFS client not connected")
        return self.client.add_bytes(data)
    
    def cat(self, cid: str) -> bytes:
        if self.client is None:
            raise RuntimeError("IPFS client not connected")
        return self.client.cat(cid)

ipfs_client = IPFSClient()

