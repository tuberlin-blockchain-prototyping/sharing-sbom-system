# Proving Service

Rust/Actix-web service for generating zero-knowledge proofs of SBOM validation and Sparse Merkle Tree validation.

## Structure

- `src/main.rs` - Application entry point and server setup
- `src/config.rs` - Configuration management
- `src/models.rs` - Request/response models and data structures
- `src/handlers.rs` - HTTP request handlers
- `src/utils.rs` - Utility functions (hashing, merkle operations, etc.)
- `methods/` - Risc0 ZKVM guest program

## API Endpoints

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy"
}
```

### `POST /prove` (Legacy SBOM Validation)
Generate a ZKP proof for SBOM validation against banned component list.

**Request:**
```json
{
  "sbom": { /* SBOM JSON object */ },
  "banned_list": ["component1", "component2", ...]
}
```

**Response:**
```json
{
  "proof": "<base64-encoded-proof>",
  "sbom_hash": "<64-char-hex-hash>",
  "image_id": ["12345678", "87654321", ...],
  "proof_info": {
    "sbom_hash": "<hash>",
    "is_valid": true,
    "banned_list": [...],
    "banned_list_info": {
      "source": "CVE Database",
      "entry_count": 42,
      "hash": "<hash>"
    },
    "image_id": [...]
  }
}
```

### `POST /prove-merkle` (New Sparse Merkle Tree Validation)
Generate a ZKP proof for Sparse Merkle Tree validation with merkle proofs.

**Request:**
```json
{
  "sparse_merkle_tree": {
    "depth": 256,
    "defaultHashes": [
      "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
      "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5",
      ...
    ]
  },
  "merkle_proofs": [
    {
      "purl": "pkg:cargo/wasm-bindgen-macro@0.2.87",
      "value": "1",
      "siblings": [
        "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5",
        ...
      ]
    },
    ...
  ]
}
```

**Response:**
```json
{
  "proof": "<base64-encoded-proof>",
  "tree_root": "<64-char-hex-hash>",
  "image_id": ["12345678", "87654321", ...],
  "proof_info": {
    "tree_root": "<hash>",
    "is_valid": true,
    "verified_proofs": 42,
    "tree_info": {
      "depth": 256,
      "root_hash": "<hash>",
      "proof_count": 42
    },
    "proofs_hash": "<hash-of-all-proofs>",
    "image_id": [...]
  }
}
```

**Sparse Merkle Tree Format:**
- `depth`: The depth of the merkle tree (typically 256 for hash-based keys)
- `defaultHashes`: Array of default hashes for each level (length = depth + 1)
  - The last element is the root hash
  - Each hash is a 64-character hex string (32 bytes)

**Merkle Proof Format:**
- `purl`: Package URL being proven
- `value`: The value stored at the leaf (typically "1" for presence)
- `siblings`: Array of sibling hashes along the path from leaf to root
  - Length must equal tree depth
  - Each hash is a 64-character hex string (32 bytes)

## Environment Variables

- `PORT` - Server port (default: 8080)

## How It Works

### Legacy SBOM Validation (`/prove`)

1. Receives SBOM JSON and banned component list
2. Computes SHA-256 hash of the SBOM
3. Creates Risc0 ZKVM execution environment with SBOM and banned list
4. Generates zero-knowledge proof that validates SBOM against banned list
5. Verifies the proof
6. Returns base64-encoded proof along with metadata

The proof proves that:
- The SBOM hash matches the provided SBOM (private input)
- The SBOM was validated against the banned list (public input)
- The validation result (is_valid) is correct

### New Merkle Tree Validation (`/prove-merkle`)

1. Receives Sparse Merkle Tree structure and list of merkle proofs
2. Validates the tree structure (depth, hash format, etc.)
3. Validates the merkle proofs (sibling count, hash format, etc.)
4. Computes the tree root from default hashes
5. Creates Risc0 ZKVM execution environment with tree and proofs
6. Generates zero-knowledge proof that validates all merkle proofs
7. Verifies the proof
8. Returns base64-encoded proof along with metadata

The proof proves that:
- The merkle tree root matches the computed root from default hashes
- Each merkle proof is valid (path from leaf to root is correct)
- All sibling hashes along each path correctly hash to the tree root
- The verification result (is_valid) is correct
- Number of verified proofs matches the input count

**Implementation Details:**
- Leaf hashes are computed from `SHA256(purl + ":" + value)`
- Path index is deterministically computed from `SHA256(purl)`
- Sibling ordering is determined by bit position in the path index
- Full verification logic is implemented in `methods/guest/src/main.rs`

For detailed implementation information, see [MERKLE_MIGRATION.md](MERKLE_MIGRATION.md).

### `POST /prove-merkle-compact` (Bandwidth-Optimized Sparse Merkle Tree Validation)
Generate a ZKP proof for Sparse Merkle Tree validation using **bitmap-compressed** merkle proofs. This endpoint reduces bandwidth by only transmitting non-default sibling hashes, using a bitmap to indicate which siblings are provided vs using hardcoded DEFAULTS.

**Request:**
```json
{
  "depth": 256,
  "root": "abd19dac7eeb8f1e98993a45d861b7877536f0c53fa0a9b7a1ceca098070d793",
  "merkle_proofs": [
    {
      "purl": "pkg:maven/org.apache.struts/struts2-core@2.5.10",
      "value": "0",
      "siblings": [
        "b9d7d779b9c4accdc2a5f8d1f370c2d0a0e5e54fec517bb875117a8f10efa9e6",
        "f07e3d9666f2a2288cbd7367b53d414d2ddcd39e94041d4c664020eeea49bb8e",
        ...
      ],
      "leaf_index": "120c5ea2cd7ffe1cc60816f7e8456d68cf2407c8b13cc04ff757be983ceeabbf",
      "bitmap": "00000000000000000000000000000000000000000000000000000000000000ff"
    }
  ]
}
```

**Response:**
```json
{
  "proof": "<base64-encoded-proof>",
  "root_hash": "abd19dac7eeb8f1e98993a45d861b7877536f0c53fa0a9b7a1ceca098070d793",
  "image_id": ["12345678", ...],
  "proof_info": {
    "root_hash": "abd19dac...",
    "is_valid": true,
    "verified_count": 2,
    "total_proofs": 2,
    "proof_type": "compact",
    "image_id": [...]
  }
}
```

**Key Differences from `/prove-merkle`:**
- **Condensed Siblings**: Only non-default siblings are provided (array length = number of 1-bits in bitmap)
- **Bitmap Field**: 32-byte hex-encoded bit-packed array indicating which siblings are provided (1) vs default (0)
- **Leaf Index**: Pre-computed SHA-256 hash of PURL (eliminates guest-side hashing)
- **Bandwidth Savings**: Typical proof size reduced from ~8KB to ~256B-1.6KB

For detailed documentation, see [COMPACT_MERKLE_PROOF.md](COMPACT_MERKLE_PROOF.md).

### `POST /debug/verify-merkle` (Debug Endpoint - No ZK)
Host-side Merkle proof verification without generating ZK proofs. Useful for testing and debugging proof generation.

**Single Proof Request:**
```json
{
  "root": "abd19dac7eeb8f1e98993a45d861b7877536f0c53fa0a9b7a1ceca098070d793",
  "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  "value": "0",
  "siblings": ["66687aadf862bd776c...", "2eeb74a6177f588d80...", ...]
}
```

**Batch Request:**
```json
{
  "root": "abd19dac7eeb8f1e98993a45d861b7877536f0c53fa0a9b7a1ceca098070d793",
  "merkle_proofs": [
    {
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "value": "0",
      "siblings": [...]
    }
  ]
}
```

**Response:**
```json
{
  "computed_root": "abd19dac...",
  "expected_root": "abd19dac...",
  "matches": true
}
```

### `POST /debug/verify-merkle-compact` (Debug Endpoint - No ZK)
Host-side compact Merkle proof verification without generating ZK proofs. Supports bitmap-compressed proofs.

**Single Proof Request:**
```json
{
  "root": "abd19dac7eeb8f1e98993a45d861b7877536f0c53fa0a9b7a1ceca098070d793",
  "purl": "pkg:maven/org.apache.struts/struts2-core@2.5.10",
  "value": "0",
  "leaf_index": "120c5ea2cd7ffe1cc60816f7e8456d68cf2407c8b13cc04ff757be983ceeabbf",
  "siblings": ["b9d7d779b9c4accdc2a5f8d1f370c2d0a0e5e54fec517bb875117a8f10efa9e6", ...],
  "bitmap": "00000000000000000000000000000000000000000000000000000000000000ff"
}
```

**Batch Request:**
```json
{
  "depth": 256,
  "root": "abd19dac7eeb8f1e98993a45d861b7877536f0c53fa0a9b7a1ceca098070d793",
  "merkle_proofs": [
    {
      "purl": "pkg:maven/org.apache.struts/struts2-core@2.5.10",
      "value": "0",
      "leaf_index": "120c5ea2cd7ffe1cc60816f7e8456d68cf2407c8b13cc04ff757be983ceeabbf",
      "siblings": [...],
      "bitmap": "00000000000000000000000000000000000000000000000000000000000000ff"
    }
  ]
}
```

**Response:**
```json
{
  "computed_root": "abd19dac...",
  "expected_root": "abd19dac...",
  "matches": true,
  "purl": "pkg:maven/org.apache.struts/struts2-core@2.5.10",
  "value": "0",
  "leaf_index": "120c5ea2cd7ffe1cc60816f7e8456d68cf2407c8b13cc04ff757be983ceeabbf",
  "bitmap_ones": 8,
  "used_provided_siblings": 8,
  "used_defaults": 248
}
```

**Key Features:**
- No ZK proof generation (fast, for testing only)
- Shows how many siblings came from bitmap vs DEFAULTS
- Validates bitmap encoding and sibling reconstruction
- Same verification logic as guest code

