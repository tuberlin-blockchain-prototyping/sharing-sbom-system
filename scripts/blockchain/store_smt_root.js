/* eslint-disable no-console */
const { ethers } = require("ethers");
const hre = require("hardhat");

async function main() {
  const address = process.env.ADDR || "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  const rootHashHex = process.env.ROOT_HASH;
  const softwareDigestHex = process.env.SOFTWARE_DIGEST;
  const sbomHashHex = process.env.SBOM_HASH;
  const ident = process.env.IDENT || "local";

  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`Invalid or missing ADDR: ${address}`);
  }
  if (!rootHashHex || !/^[0-9a-fA-F]{64}$/.test(rootHashHex)) {
    throw new Error(`Invalid or missing ROOT_HASH: ${rootHashHex}`);
  }
  if (!softwareDigestHex || !/^[0-9a-fA-F]{64}$/.test(softwareDigestHex)) {
    throw new Error(`Invalid or missing SOFTWARE_DIGEST: ${softwareDigestHex}`);
  }
  if (!sbomHashHex || !/^[0-9a-fA-F]{64}$/.test(sbomHashHex)) {
    throw new Error(`Invalid or missing SBOM_HASH: ${sbomHashHex}`);
  }

  const [signer] = await hre.ethers.getSigners();
  console.log("Using signer:", signer.address);
  
  const abi = [
    "function registerSMTRoot(bytes32 rootHash, bytes32 softwareDigest, bytes32 sbomHash, string calldata identifier) external",
    "function getSMTRoot(bytes32 rootHash) external view returns (tuple(bytes32 rootHash, bytes32 softwareDigest, bytes32 sbomHash, string identifier, uint256 timestamp, address submitter))",
    "function existsSMTRoot(bytes32 rootHash) external view returns (bool)",
    "event SMTRootRegistered(bytes32 indexed rootHash, bytes32 softwareDigest, bytes32 sbomHash, string identifier, address indexed submitter, uint256 timestamp)"
  ];
  
  const contract = new ethers.Contract(address, abi, signer);
  
  const rootHashBytes32 = "0x" + rootHashHex;
  const softwareDigestBytes32 = "0x" + softwareDigestHex;
  const sbomHashBytes32 = "0x" + sbomHashHex;
  
  const exists = await contract.existsSMTRoot(rootHashBytes32);
  if (exists) {
    console.log("SMT root hash already exists in contract, skipping registration");
    console.log("Root Hash:", rootHashBytes32);
    try {
      const entry = await contract.getSMTRoot(rootHashBytes32);
      console.log("Existing entry:");
      console.log("  Software Digest:", entry.softwareDigest);
      console.log("  SBOM Hash:", entry.sbomHash);
      console.log("  Identifier:", entry.identifier);
      console.log("  Timestamp:", new Date(Number(entry.timestamp) * 1000).toISOString());
      console.log("  Submitter:", entry.submitter);
      console.log("SKIPPED");
      return;
    } catch (e) {
      console.error("Could not retrieve entry details:", e.message);
      throw new Error("SMT root hash already stored but could not retrieve details.");
    }
  }
  
  console.log("Storing SMT Root:");
  console.log("  Root Hash:", rootHashBytes32);
  console.log("  Software Digest:", softwareDigestBytes32);
  console.log("  SBOM Hash:", sbomHashBytes32);
  console.log("  Identifier:", ident);
  
  const tx = await contract.registerSMTRoot(
    rootHashBytes32,
    softwareDigestBytes32,
    sbomHashBytes32,
    ident
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

