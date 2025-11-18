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

