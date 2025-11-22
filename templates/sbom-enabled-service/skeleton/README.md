# ${{ values.name }}

${{ values.description }}

## SBOM Integration

This service is integrated with the SBOM Sharing System:

{% if values.enableZkpProof %}
- ✅ **ZKP Proof Generation**: Automatic Zero-Knowledge Proof generation during CI/CD
{% endif %}
{% if values.storeOnIpfs %}
- ✅ **IPFS Storage**: Proofs stored on IPFS for decentralized access
{% endif %}
{% if values.writeToBlockchain %}
- ✅ **Blockchain Recording**: SBOM metadata recorded on blockchain
{% endif %}

## Getting Started

### Prerequisites

{% if values.language == 'rust' %}
- Rust 1.70+
- Cargo
{% elif values.language == 'python' %}
- Python 3.11+
- pip or poetry
{% elif values.language == 'nodejs' %}
- Node.js 18+
- npm or yarn
{% endif %}

### Development

{% if values.language == 'rust' %}
```bash
cargo build
cargo run
```
{% elif values.language == 'python' %}
```bash
pip install -r requirements.txt
python app.py
```
{% elif values.language == 'nodejs' %}
```bash
npm install
npm start
```
{% endif %}

### Building Docker Image

```bash
docker build -t ${{ values.name }}:latest .
docker push <your-registry>/${{ values.name }}:latest
```

## CI/CD Pipeline

The GitHub Actions workflow automatically:
1. Builds Docker image
2. Generates SBOM using Syft
3. Fetches banned component list from CVE database
{% if values.enableZkpProof %}
4. Generates Zero-Knowledge Proof
{% endif %}
{% if values.storeOnIpfs %}
5. Stores proof on IPFS
{% endif %}
{% if values.writeToBlockchain %}
6. Records metadata on blockchain
{% endif %}

## Architecture

This service is part of the SBOM Sharing System:
- **Proving Service**: Generates ZKP proofs
- **Verifier Service**: Verifies ZKP proofs
- **IPFS Service**: Stores proofs on IPFS
- **Blockchain**: Records SBOM metadata

## License

Apache-2.0
