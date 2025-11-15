# Proving Service

Rust/Actix-web service for generating zero-knowledge proofs of SBOM validation.

## Structure

- `src/main.rs` - Application entry point and server setup
- `src/config.rs` - Configuration management
- `src/models.rs` - Request/response models and data structures
- `src/handlers.rs` - HTTP request handlers
- `src/utils.rs` - Utility functions (hashing, etc.)
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

### `POST /prove`
Generate a ZKP proof for SBOM validation.

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

## Environment Variables

- `PORT` - Server port (default: 8080)

## How It Works

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

