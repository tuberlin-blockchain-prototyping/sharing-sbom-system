import subprocess
import logging
import os
from config import Config

logger = logging.getLogger(__name__)


class BlockchainClient:
    def __init__(self):
        self.contract_address = Config.BLOCKCHAIN_CONTRACT_ADDRESS
        self.namespace = Config.BLOCKCHAIN_NAMESPACE
        self.script_path = Config.BLOCKCHAIN_SCRIPT_PATH

    async def store_merkle_proof(self, root_hash: str, ipfs_cid: str, banned_list_hash: str, compliant: bool) -> str:
        kubectl_cmd = [
            "kubectl", "get", "pods",
            "-n", self.namespace,
            "-l", "app=hardhat-node",
            "-o", "jsonpath={.items[0].metadata.name}"
        ]

        try:
            result = subprocess.run(
                kubectl_cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            hardhat_pod = result.stdout.strip()

            if not hardhat_pod:
                raise Exception("Hardhat node pod not found")

            logger.info(f"Found Hardhat pod: {hardhat_pod}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to find Hardhat pod: {e.stderr}")
            raise Exception(f"Failed to find Hardhat pod: {e.stderr}")

        script_name = os.path.basename(self.script_path)
        local_script_path = f"scripts/blockchain/{script_name}"

        copy_cmd = [
            "kubectl", "cp",
            local_script_path,
            f"{self.namespace}/{hardhat_pod}:{self.script_path}"
        ]

        try:
            subprocess.run(copy_cmd, check=True, timeout=10)
            logger.info(f"Copied script to pod: {script_name}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to copy script: {e}")
            raise Exception(f"Failed to copy script to pod")

        env_vars = {
            "ADDR": self.contract_address,
            "ROOT_HASH": root_hash,
            "IPFS_CID": ipfs_cid,
            "BANNED_LIST_HASH": banned_list_hash,
            "COMPLIANT": "true" if compliant else "false"
        }

        env_str = " ".join([f"{k}='{v}'" for k, v in env_vars.items()])

        exec_cmd = [
            "kubectl", "exec", "-n", self.namespace, hardhat_pod, "--",
            "sh", "-c",
            f"cd /workspace && {env_str} npx hardhat run {self.script_path} --network localhost"
        ]

        logger.info(
            f"Executing blockchain script with root_hash={root_hash}, compliant={compliant}")

        try:
            result = subprocess.run(
                exec_cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=Config.BLOCKCHAIN_TIMEOUT
            )

            output_lines = result.stdout.strip().split('\n')
            tx_hash = output_lines[-1] if output_lines else None

            if not tx_hash or not tx_hash.startswith("0x") or len(tx_hash) != 66:
                logger.error(f"Invalid transaction hash format: {tx_hash}")
                logger.error(f"Script output: {result.stdout}")
                raise Exception("Failed to extract valid transaction hash")

            logger.info(f"Transaction successful: {tx_hash}")
            return tx_hash

        except subprocess.CalledProcessError as e:
            logger.error(f"Blockchain script failed: {e.stderr}")
            logger.error(f"Script output: {e.stdout}")
            raise Exception(f"Blockchain transaction failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("Blockchain script timed out")
            raise Exception("Blockchain transaction timed out")
