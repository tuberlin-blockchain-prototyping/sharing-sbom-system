# IPFS Service

Flask service for storing and retrieving ZKP proofs on IPFS.

## Structure

- `app.py` - Application factory and entry point
- `config.py` - Configuration management
- `models.py` - SQLAlchemy database models
- `routes.py` - API routes (blueprint)
- `ipfs_client.py` - IPFS client wrapper
- `utils.py` - Utility functions

## Database

Uses SQLite database (`/data/ipfs.db`) to store mappings:
- `sbom_hash` (64 hex chars) -> `ipfs_cid`
- Timestamps for audit trail

## API Endpoints

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "ipfs_connected": true
}
```

### `POST /store`
Store a proof on IPFS and create mapping.

**Request:**
```json
{
  "proof": "<base64-encoded-proof>",
  "sbom_hash": "<64-char-hex-hash>"
}
```

**Response:**
```json
{
  "ipfs_cid": "Qm...",
  "sbom_hash": "a1b2c3..."
}
```

### `GET /retrieve/<sbom_hash>`
Retrieve proof from IPFS using SBOM hash.

**Response:**
```json
{
  "proof": "<base64-encoded-proof>",
  "ipfs_cid": "Qm...",
  "sbom_hash": "a1b2c3..."
}
```

### `GET /list?limit=100&offset=0`
List all stored mappings (paginated).

**Response:**
```json
{
  "total": 42,
  "limit": 100,
  "offset": 0,
  "mappings": [
    {
      "sbom_hash": "a1b2c3...",
      "ipfs_cid": "Qm...",
      "created_at": "2024-01-01T00:00:00"
    }
  ]
}
```

## Environment Variables

- `PORT` - Server port (default: 8080)
- `IPFS_HOST` - IPFS node host (default: localhost)
- `IPFS_PORT` - IPFS API port (default: 5001)
- `IPFS_PROTOCOL` - IPFS protocol (default: http)
- `DB_PATH` - SQLite database path (default: /data/ipfs.db)

