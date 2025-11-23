/* eslint-disable no-console */
const { ethers } = require("ethers");
const hre = require("hardhat");

async function main() {
  const address = process.env.ADDR || "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  const rootHashHex = process.env.ROOT_HASH;
  const ipfsCid = process.env.IPFS_CID;
  const bannedListHashHex = process.env.BANNED_LIST_HASH;
  const compliant = process.env.COMPLIANT === "true";

  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`Invalid or missing ADDR: ${address}`);
  }
  if (!rootHashHex || !/^[0-9a-fA-F]{64}$/.test(rootHashHex)) {
    throw new Error(`Invalid or missing ROOT_HASH: ${rootHashHex}`);
  }
  if (!ipfsCid) {
    throw new Error(`Missing IPFS_CID`);
  }
  if (!bannedListHashHex || !/^[0-9a-fA-F]{64}$/.test(bannedListHashHex)) {
    throw new Error(`Invalid or missing BANNED_LIST_HASH: ${bannedListHashHex}`);
  }

  const [signer] = await hre.ethers.getSigners();
  console.log("Using signer:", signer.address);
  
  const abi = [
    "function registerMerkleProof(bytes32 rootHash, string calldata ipfsCid, bytes32 bannedListHash, bool compliant) external",
    "function getMerkleProof(bytes32 rootHash, bytes32 bannedListHash) external view returns (tuple(bytes32 rootHash, string ipfsCid, bytes32 bannedListHash, bool compliant, uint256 timestamp, address prover))",
    "function existsMerkleProof(bytes32 rootHash, bytes32 bannedListHash) external view returns (bool)",
    "event MerkleProofRegistered(bytes32 indexed rootHash, string ipfsCid, bytes32 bannedListHash, bool compliant, address indexed prover, uint256 timestamp)"
  ];
  
  const contract = new ethers.Contract(address, abi, signer);
  
  const rootHashBytes32 = "0x" + rootHashHex;
  const bannedListHashBytes32 = "0x" + bannedListHashHex;
  
  const exists = await contract.existsMerkleProof(rootHashBytes32, bannedListHashBytes32);
  if (exists) {
    console.error("ERROR: Merkle proof already exists in contract");
    console.error("Root Hash:", rootHashBytes32);
    console.error("Banned List Hash:", bannedListHashBytes32);
    try {
      const entry = await contract.getMerkleProof(rootHashBytes32, bannedListHashBytes32);
      console.error("Existing entry:");
      console.error("  IPFS CID:", entry.ipfsCid);
      console.error("  Compliant:", entry.compliant);
      console.error("  Timestamp:", new Date(Number(entry.timestamp) * 1000).toISOString());
      console.error("  Prover:", entry.prover);
    } catch (e) {
      console.error("Could not retrieve entry details:", e.message);
    }
    throw new Error("Merkle proof already stored.");
  }
  
  console.log("Storing Merkle Proof:");
  console.log("  Root Hash:", rootHashBytes32);
  console.log("  IPFS CID:", ipfsCid);
  console.log("  Banned List Hash:", bannedListHashBytes32);
  console.log("  Compliant:", compliant);
  
  const tx = await contract.registerMerkleProof(
    rootHashBytes32,
    ipfsCid,
    bannedListHashBytes32,
    compliant
  );
  
  console.log("Transaction sent:", tx.hash);
  const receipt = await tx.wait();
  console.log("Transaction confirmed:", receipt.hash);
  console.log(receipt.hash);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

