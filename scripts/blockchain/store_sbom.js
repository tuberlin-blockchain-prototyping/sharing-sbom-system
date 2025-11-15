/* eslint-disable no-console */
const { ethers } = require("ethers");
const hre = require("hardhat");

async function main() {
  const address = process.env.ADDR;
  const hashHex = process.env.HASH; // 64 hex chars
  const softwareDigestHex = process.env.SOFTWARE_DIGEST; // 64 hex chars (sha256 without "sha256:" prefix)
  const ident = process.env.IDENT || "local";
  const imageIdStr = process.env.IMAGE_ID; // comma-separated u32s
  const ipfsCid = process.env.IPFS_CID;
  const isValid = process.env.IS_VALID === "true";
  const bannedListHashHex = process.env.BANNED_LIST_HASH; // 64 hex chars

  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`Invalid or missing ADDR: ${address}`);
  }
  if (!hashHex || !/^[0-9a-fA-F]{64}$/.test(hashHex)) {
    throw new Error(`Invalid or missing HASH: ${hashHex}`);
  }
  if (!softwareDigestHex || !/^[0-9a-fA-F]{64}$/.test(softwareDigestHex)) {
    throw new Error(`Invalid or missing SOFTWARE_DIGEST: ${softwareDigestHex}`);
  }
  if (!imageIdStr) {
    throw new Error(`Missing IMAGE_ID`);
  }
  if (!ipfsCid) {
    throw new Error(`Missing IPFS_CID`);
  }
  if (!bannedListHashHex || !/^[0-9a-fA-F]{64}$/.test(bannedListHashHex)) {
    throw new Error(`Invalid or missing BANNED_LIST_HASH: ${bannedListHashHex}`);
  }

  // Use hardhat runtime provider signer on selected network
  const [signer] = await hre.ethers.getSigners();
  console.log("Using signer:", signer.address);
  
  const abi = [
    "function storeSBOM(bytes32 hash, bytes32 softwareDigest, string identifier, bytes32 imageId, string ipfsCid, bool isValid, bytes32 bannedListHash) external",
    "function getSBOM(bytes32 hash) external view returns (tuple(bytes32 hash, bytes32 softwareDigest, string identifier, bytes32 imageId, string ipfsCid, bool isValid, bytes32 bannedListHash, uint256 timestamp, address submitter))",
    "function exists(bytes32 hash) external view returns (bool)",
    "event SBOMStored(bytes32 indexed hash, bytes32 softwareDigest, string identifier, bytes32 imageId, string ipfsCid, bool isValid, bytes32 bannedListHash, address indexed submitter, uint256 timestamp)"
  ];
  
  const contract = new ethers.Contract(address, abi, signer);
  
  const hashBytes32 = "0x" + hashHex;
  const softwareDigestBytes32 = "0x" + softwareDigestHex;
  
  // Check if hash already exists
  const exists = await contract.exists(hashBytes32);
  if (exists) {
    console.error("ERROR: SBOM hash already exists in contract");
    console.error("Hash:", hashBytes32);
    try {
      const entry = await contract.getSBOM(hashBytes32);
      console.error("Existing entry:");
      console.error("  Software Digest:", entry.softwareDigest);
      console.error("  Identifier:", entry.identifier);
      console.error("  IPFS CID:", entry.ipfsCid);
      console.error("  Timestamp:", new Date(Number(entry.timestamp) * 1000).toISOString());
      console.error("  Submitter:", entry.submitter);
    } catch (e) {
      console.error("Could not retrieve entry details:", e.message);
    }
    throw new Error("SBOM hash already stored. Each run needs a unique SBOM hash.");
  }
  
  // Convert IMAGE_ID from comma-separated u32s to bytes32
  const u32s = imageIdStr.split(",").map(s => parseInt(s.trim(), 10));
  if (u32s.length !== 8) {
    throw new Error(`Expected 8 u32 values, got ${u32s.length}`);
  }
  
  const buffer = new ArrayBuffer(32);
  const view = new DataView(buffer);
  for (let i = 0; i < 8; i++) {
    view.setUint32(i * 4, u32s[i], true);
  }
  
  const imageIdBytes32 = ethers.hexlify(new Uint8Array(buffer));
  const bannedListHashBytes32 = "0x" + bannedListHashHex;
  
  console.log("Storing SBOM:");
  console.log("  Hash:", hashBytes32);
  console.log("  Software Digest:", softwareDigestBytes32);
  console.log("  Identifier:", ident);
  console.log("  Image ID:", imageIdBytes32);
  console.log("  IPFS CID:", ipfsCid);
  console.log("  Is Valid:", isValid);
  console.log("  Banned List Hash:", bannedListHashBytes32);
  
  const tx = await contract.storeSBOM(
    hashBytes32,
    softwareDigestBytes32,
    ident,
    imageIdBytes32,
    ipfsCid,
    isValid,
    bannedListHashBytes32
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

