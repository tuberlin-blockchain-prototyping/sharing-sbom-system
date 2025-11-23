#!/usr/bin/env bash
# Verifies that an SMT root hash exists on the blockchain:
# 1. Queries blockchain contract for SMT root entry
# 2. Displays entry details if found
# Usage: ROOT_HASH=<hash> ./verify-cicd-run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACT_ADDR="0x5FbDB2315678afecb367f032d93F642f64180aa3"

[ -z "${ROOT_HASH:-}" ] && { echo "ERROR: ROOT_HASH not set"; echo "Usage: ROOT_HASH=<hash> $0"; exit 1; }

echo "=== Verify CI/CD Run ==="
echo "Root Hash: $ROOT_HASH"
echo ""

HARDHAT_POD=$(kubectl get pods -n blockchain -l app=hardhat-node -o jsonpath='{.items[0].metadata.name}')
[ -z "$HARDHAT_POD" ] && { echo "ERROR: Hardhat pod not found"; exit 1; }

cat > /tmp/check_smt.js << 'EOF'
const { ethers } = require("ethers");
const hre = require("hardhat");

async function main() {
  const address = process.env.ADDR || "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  const rootHashHex = process.env.ROOT_HASH;

  if (!rootHashHex || !/^[0-9a-fA-F]{64}$/.test(rootHashHex)) {
    throw new Error(`Invalid ROOT_HASH: ${rootHashHex}`);
  }

  const [signer] = await hre.ethers.getSigners();
  const abi = [
    "function getSMTRoot(bytes32 rootHash) external view returns (tuple(bytes32 rootHash, bytes32 softwareDigest, bytes32 sbomHash, string identifier, uint256 timestamp, address submitter))",
    "function existsSMTRoot(bytes32 rootHash) external view returns (bool)"
  ];
  
  const contract = new ethers.Contract(address, abi, signer);
  const rootHashBytes32 = "0x" + rootHashHex;
  
  const exists = await contract.existsSMTRoot(rootHashBytes32);
  if (!exists) {
    console.log("NOT_FOUND");
    process.exit(1);
  }
  
  const entry = await contract.getSMTRoot(rootHashBytes32);
  console.log(JSON.stringify({
    rootHash: entry.rootHash,
    softwareDigest: entry.softwareDigest,
    sbomHash: entry.sbomHash,
    identifier: entry.identifier,
    timestamp: entry.timestamp.toString(),
    submitter: entry.submitter
  }, null, 2));
}

main().catch((e) => {
  console.error("ERROR:", e.message);
  process.exit(1);
});
EOF

kubectl cp /tmp/check_smt.js "blockchain/$HARDHAT_POD:/workspace/check_smt.js" > /dev/null 2>&1

CHECK_OUTPUT=$(kubectl exec -n blockchain "$HARDHAT_POD" -- sh -c "
    cd /workspace && \
    ADDR='$CONTRACT_ADDR' \
    ROOT_HASH='$ROOT_HASH' \
    npx hardhat run check_smt.js --network localhost 2>&1
" || echo "NOT_FOUND")

echo "$CHECK_OUTPUT" | grep -q "NOT_FOUND" && { echo "❌ SMT Root NOT found on blockchain"; exit 1; }

echo "✅ SMT Root found on blockchain!"
echo ""
echo "$CHECK_OUTPUT" | jq .
echo ""
echo "=== Complete ==="
echo "✅ Root Hash: $ROOT_HASH"

rm -f /tmp/check_smt.js
