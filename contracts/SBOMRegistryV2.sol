// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SBOMRegistryV2 {
    struct SMTRootEntry {
        bytes32 rootHash;
        bytes32 softwareDigest;
        bytes32 sbomHash;
        string identifier;
        uint256 timestamp;
        address submitter;
    }

    struct MerkleProofEntry {
        bytes32 rootHash;
        string ipfsCid;
        bytes32 bannedListHash;
        bool compliant;
        uint256 timestamp;
        address prover;
    }

    mapping(bytes32 => SMTRootEntry) private smtRoots;
    mapping(bytes32 => MerkleProofEntry) private merkleProofs;
    
    bytes32[] private smtRootHashes;
    bytes32[] private merkleProofHashes;

    event SMTRootRegistered(
        bytes32 indexed rootHash,
        bytes32 softwareDigest,
        bytes32 sbomHash,
        string identifier,
        address indexed submitter,
        uint256 timestamp
    );

    event MerkleProofRegistered(
        bytes32 indexed rootHash,
        string ipfsCid,
        bytes32 bannedListHash,
        bool compliant,
        address indexed prover,
        uint256 timestamp
    );

    function registerSMTRoot(
        bytes32 rootHash,
        bytes32 softwareDigest,
        bytes32 sbomHash,
        string calldata identifier
    ) external {
        require(smtRoots[rootHash].timestamp == 0, "SMT root already registered");
        
        SMTRootEntry memory entry = SMTRootEntry({
            rootHash: rootHash,
            softwareDigest: softwareDigest,
            sbomHash: sbomHash,
            identifier: identifier,
            timestamp: block.timestamp,
            submitter: msg.sender
        });
        
        smtRoots[rootHash] = entry;
        smtRootHashes.push(rootHash);
        
        emit SMTRootRegistered(
            rootHash,
            softwareDigest,
            sbomHash,
            identifier,
            msg.sender,
            block.timestamp
        );
    }

    function registerMerkleProof(
        bytes32 rootHash,
        string calldata ipfsCid,
        bytes32 bannedListHash,
        bool compliant
    ) external {
        bytes32 proofKey = keccak256(abi.encodePacked(rootHash, bannedListHash));
        require(merkleProofs[proofKey].timestamp == 0, "Merkle proof already registered");
        
        MerkleProofEntry memory entry = MerkleProofEntry({
            rootHash: rootHash,
            ipfsCid: ipfsCid,
            bannedListHash: bannedListHash,
            compliant: compliant,
            timestamp: block.timestamp,
            prover: msg.sender
        });
        
        merkleProofs[proofKey] = entry;
        merkleProofHashes.push(proofKey);
        
        emit MerkleProofRegistered(
            rootHash,
            ipfsCid,
            bannedListHash,
            compliant,
            msg.sender,
            block.timestamp
        );
    }

    function getSMTRoot(bytes32 rootHash) external view returns (SMTRootEntry memory) {
        require(smtRoots[rootHash].timestamp != 0, "SMT root not found");
        return smtRoots[rootHash];
    }

    function getMerkleProof(bytes32 rootHash, bytes32 bannedListHash) external view returns (MerkleProofEntry memory) {
        bytes32 proofKey = keccak256(abi.encodePacked(rootHash, bannedListHash));
        require(merkleProofs[proofKey].timestamp != 0, "Merkle proof not found");
        return merkleProofs[proofKey];
    }

    function existsSMTRoot(bytes32 rootHash) external view returns (bool) {
        return smtRoots[rootHash].timestamp != 0;
    }

    function existsMerkleProof(bytes32 rootHash, bytes32 bannedListHash) external view returns (bool) {
        bytes32 proofKey = keccak256(abi.encodePacked(rootHash, bannedListHash));
        return merkleProofs[proofKey].timestamp != 0;
    }

    function listSMTRootHashes() external view returns (bytes32[] memory) {
        return smtRootHashes;
    }

    function listMerkleProofHashes() external view returns (bytes32[] memory) {
        return merkleProofHashes;
    }
}

