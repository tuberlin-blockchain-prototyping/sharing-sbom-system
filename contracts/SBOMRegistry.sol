// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SBOMRegistry {
    struct SBOMEntry {
        bytes32 hash;
        string image;
        string identifier;
        bytes32 imageId;
        string ipfsCid;
        bool isValid;
        bytes32 bannedListHash;
        uint256 timestamp;
        address submitter;
    }

    mapping(bytes32 => SBOMEntry) private entries;
    bytes32[] private hashes;

    event SBOMStored(
        bytes32 indexed hash,
        string image,
        string identifier,
        bytes32 imageId,
        string ipfsCid,
        bool isValid,
        bytes32 bannedListHash,
        address indexed submitter,
        uint256 timestamp
    );

    function storeSBOM(
        bytes32 hash,
        string calldata image,
        string calldata identifier,
        bytes32 imageId,
        string calldata ipfsCid,
        bool isValid,
        bytes32 bannedListHash
    ) external {
        require(entries[hash].timestamp == 0, "Already stored");
        SBOMEntry memory entry = SBOMEntry({
            hash: hash,
            image: image,
            identifier: identifier,
            imageId: imageId,
            ipfsCid: ipfsCid,
            isValid: isValid,
            bannedListHash: bannedListHash,
            timestamp: block.timestamp,
            submitter: msg.sender
        });
        entries[hash] = entry;
        hashes.push(hash);
        emit SBOMStored(hash, image, identifier, imageId, ipfsCid, isValid, bannedListHash, msg.sender, block.timestamp);
    }

    function getSBOM(bytes32 hash) external view returns (SBOMEntry memory) {
        require(entries[hash].timestamp != 0, "Not found");
        return entries[hash];
    }

    function exists(bytes32 hash) external view returns (bool) {
        return entries[hash].timestamp != 0;
    }

    function listHashes() external view returns (bytes32[] memory) {
        return hashes;
    }
}

