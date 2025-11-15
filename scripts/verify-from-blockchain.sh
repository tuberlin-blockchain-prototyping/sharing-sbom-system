#!/bin/bash
set -euo pipefail

# Usage: ./verify-from-blockchain.sh <sbom_hash>

CONTRACT_ADDR="0x5FbDB2315678afecb367f032d93F642f64180aa3"
RPC_URL="${RPC_URL:-http://hardhat-node.blockchain.svc.cluster.local:8545}"

IPFS_PORT=8082
VERIFIER_PORT=8083

if ! curl -s --max-time 2 "http://ipfs-service.sharing-sbom-system.svc.cluster.local/health" >/dev/null 2>&1; then
  pkill -f "kubectl port-forward.*ipfs-service" 2>/dev/null || true
  pkill -f "kubectl port-forward.*verifier-service" 2>/dev/null || true
  sleep 1
  kubectl port-forward -n sharing-sbom-system svc/ipfs-service $IPFS_PORT:80 >/dev/null 2>&1 &
  kubectl port-forward -n sharing-sbom-system svc/verifier-service $VERIFIER_PORT:80 >/dev/null 2>&1 &
  sleep 2
  IPFS_SERVICE_URL="http://localhost:$IPFS_PORT"
  VERIFIER_SERVICE_URL="http://localhost:$VERIFIER_PORT"
  trap "pkill -f 'kubectl port-forward.*ipfs-service'; pkill -f 'kubectl port-forward.*verifier-service'" EXIT
else
  IPFS_SERVICE_URL="${IPFS_SERVICE_URL:-http://ipfs-service.sharing-sbom-system.svc.cluster.local}"
  VERIFIER_SERVICE_URL="${VERIFIER_SERVICE_URL:-http://verifier-service.sharing-sbom-system.svc.cluster.local}"
fi

SBOM_HASH="${1:-}"

HARDHAT_POD=$(kubectl get pods -n blockchain -l app=hardhat-node -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -z "$HARDHAT_POD" ] && { echo "ERROR: Hardhat node not found"; exit 1; }

if [ -z "$SBOM_HASH" ]; then
  LIST_SCRIPT=$(mktemp)
  cat > "$LIST_SCRIPT" << 'EOF'
const { ethers } = require("ethers");
(async () => {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://localhost:8545");
  const contract = new ethers.Contract(process.env.CONTRACT_ADDR, ["function listHashes() external view returns (bytes32[])"], provider);
  const hashes = await contract.listHashes();
  if (hashes.length === 0) {
    console.log("No SBOM hashes found.");
    process.exit(0);
  }
  console.log(`Found ${hashes.length} SBOM hash(es):\n`);
  hashes.forEach((h, i) => console.log(`${i + 1}. ${h.replace(/^0x/, '').toLowerCase()}`));
  console.log(`\nUsage: $0 ${hashes[0].replace(/^0x/, '').toLowerCase()}`);
})();
EOF
  kubectl cp "$LIST_SCRIPT" "blockchain/$HARDHAT_POD:/workspace/list.js" >/dev/null 2>&1
  kubectl exec -n blockchain "$HARDHAT_POD" -- sh -c "cd /workspace && RPC_URL='$RPC_URL' CONTRACT_ADDR='$CONTRACT_ADDR' node list.js"
  kubectl exec -n blockchain "$HARDHAT_POD" -- rm -f /workspace/list.js >/dev/null 2>&1
  rm -f "$LIST_SCRIPT"
  exit 0
fi

[[ ! "$SBOM_HASH" =~ ^[0-9a-fA-F]{64}$ ]] && { echo "ERROR: Invalid hash format"; exit 1; }

echo "Verifying SBOM: $SBOM_HASH"

QUERY_SCRIPT=$(mktemp)
cat > "$QUERY_SCRIPT" << 'EOF'
const { ethers } = require("ethers");
(async () => {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://localhost:8545");
  const abi = [
    "function getSBOM(bytes32 hash) external view returns (tuple(bytes32 hash, bytes32 softwareDigest, string identifier, bytes32 imageId, string ipfsCid, bool isValid, bytes32 bannedListHash, uint256 timestamp, address submitter))",
    "function exists(bytes32 hash) external view returns (bool)"
  ];
  const contract = new ethers.Contract(process.env.CONTRACT_ADDR, abi, provider);
  const hashBytes32 = "0x" + process.env.SBOM_HASH;
  if (!(await contract.exists(hashBytes32))) {
    console.error("ERROR: SBOM hash not found");
    process.exit(1);
  }
  const entry = await contract.getSBOM(hashBytes32);
  console.log(JSON.stringify({
    hash: entry.hash,
    softwareDigest: entry.softwareDigest,
    identifier: entry.identifier,
    imageId: entry.imageId,
    ipfsCid: entry.ipfsCid,
    isValid: entry.isValid,
    bannedListHash: entry.bannedListHash,
    timestamp: entry.timestamp.toString(),
    submitter: entry.submitter
  }));
})();
EOF

kubectl cp "$QUERY_SCRIPT" "blockchain/$HARDHAT_POD:/workspace/query.js" >/dev/null 2>&1
BLOCKCHAIN_DATA=$(kubectl exec -n blockchain "$HARDHAT_POD" -- sh -c "cd /workspace && RPC_URL='$RPC_URL' CONTRACT_ADDR='$CONTRACT_ADDR' SBOM_HASH='$SBOM_HASH' node query.js")
[ $? -ne 0 ] && { echo "$BLOCKCHAIN_DATA"; exit 1; }
kubectl exec -n blockchain "$HARDHAT_POD" -- rm -f /workspace/query.js >/dev/null 2>&1
rm -f "$QUERY_SCRIPT"

IPFS_CID=$(echo "$BLOCKCHAIN_DATA" | jq -r '.ipfsCid')
BLOCKCHAIN_IS_VALID=$(echo "$BLOCKCHAIN_DATA" | jq -r '.isValid')
SOFTWARE_DIGEST=$(echo "$BLOCKCHAIN_DATA" | jq -r '.softwareDigest' | sed 's/^0x//')
echo "Blockchain: CID=$IPFS_CID, Valid=$BLOCKCHAIN_IS_VALID, Digest=sha256:$SOFTWARE_DIGEST"

HTTP_CODE=$(curl -s -o /tmp/ipfs_resp.json -w "%{http_code}" --max-time 5 "$IPFS_SERVICE_URL/retrieve/$SBOM_HASH")
[ "$HTTP_CODE" != "200" ] && { echo "ERROR: IPFS retrieval failed ($HTTP_CODE)"; cat /tmp/ipfs_resp.json | jq . 2>/dev/null || cat /tmp/ipfs_resp.json; rm -f /tmp/ipfs_resp.json; exit 1; }

PROOF=$(cat /tmp/ipfs_resp.json | jq -r '.proof')
RETRIEVED_CID=$(cat /tmp/ipfs_resp.json | jq -r '.ipfs_cid')
rm -f /tmp/ipfs_resp.json

[ "$IPFS_CID" != "$RETRIEVED_CID" ] && echo "WARNING: CID mismatch: $IPFS_CID vs $RETRIEVED_CID"
echo "Retrieved proof from IPFS (${#PROOF} chars)"

PROOF_FILE=$(mktemp)
echo -n "$PROOF" > "$PROOF_FILE"
PAYLOAD_FILE=$(mktemp)
jq -n --rawfile proof "$PROOF_FILE" '{proof: $proof}' > "$PAYLOAD_FILE"

VERIFY_RESPONSE=$(curl -s -X POST "$VERIFIER_SERVICE_URL/verify" -H "Content-Type: application/json" -d @"$PAYLOAD_FILE")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$VERIFIER_SERVICE_URL/verify" -H "Content-Type: application/json" -d @"$PAYLOAD_FILE")
rm -f "$PAYLOAD_FILE" "$PROOF_FILE"

[ "$HTTP_CODE" != "200" ] && { echo "ERROR: Verification failed ($HTTP_CODE)"; echo "$VERIFY_RESPONSE"; exit 1; }

VERIFIED_HASH=$(echo "$VERIFY_RESPONSE" | jq -r '.sbom_hash')
VERIFIED_VALID=$(echo "$VERIFY_RESPONSE" | jq -r '.is_valid')

[ "$SBOM_HASH" != "$(echo "$VERIFIED_HASH" | tr '[:upper:]' '[:lower:]')" ] && { echo "ERROR: Hash mismatch"; exit 1; }
[ "$BLOCKCHAIN_IS_VALID" != "$VERIFIED_VALID" ] && { echo "ERROR: Validation mismatch"; exit 1; }

echo "Verification passed: Valid=$VERIFIED_VALID"

