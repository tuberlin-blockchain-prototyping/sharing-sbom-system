# Backstage Integration

This document describes how to set up and use Backstage with the SBOM Sharing System.

## Overview

Backstage provides a unified developer portal for:
- **Service Catalog**: View all microservices and their status
- **SBOM Dashboard**: Monitor SBOM validation and ZKP proofs
- **API Documentation**: Interactive API explorer
- **Kubernetes Integration**: Live service health and metrics
- **Service Templates**: Scaffold new SBOM-enabled services

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Backstage Portal                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Service    │  │     SBOM     │  │     API      │  │
│  │   Catalog    │  │   Dashboard  │  │   Explorer   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
           │                  │                  │
           ├──────────────────┼──────────────────┤
           ▼                  ▼                  ▼
┌──────────────────────────────────────────────────────────┐
│              SBOM Backend Plugin (Custom)                 │
│  - Fetches SBOMs from blockchain                         │
│  - Retrieves proofs from IPFS                            │
│  - Verifies proofs via verifier-service                  │
│  - Monitors service health                               │
└──────────────────────────────────────────────────────────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌─────────────────┐  ┌─────────────┐  ┌──────────────────┐
│   Blockchain    │  │    IPFS     │  │     Services     │
│  (SBOMRegistry) │  │   Storage   │  │ (Proving/Verify) │
└─────────────────┘  └─────────────┘  └──────────────────┘
```

## Setup Instructions

### 1. Install Dependencies

```bash
cd sbom
yarn install
```

### 2. Configure Environment Variables

Create `.env` file in `sbom/` directory:

```bash
# GitHub Token for catalog integration
GITHUB_TOKEN=ghp_your_token_here

# Kubernetes Cluster URL
K8S_CLUSTER_URL=https://kubernetes.default.svc

# Service URLs (defaults work in-cluster)
BLOCKCHAIN_RPC_URL=http://hardhat-node.blockchain.svc.cluster.local:8545
PROVING_SERVICE_URL=http://proving-service.sharing-sbom-system.svc.cluster.local
VERIFIER_SERVICE_URL=http://verifier-service.sharing-sbom-system.svc.cluster.local
IPFS_SERVICE_URL=http://ipfs-service.sharing-sbom-system.svc.cluster.local
```

### 3. Build Backstage Application

```bash
cd sbom
yarn install
yarn tsc
yarn build:backend
```

### 4. Build Docker Image

```bash
cd sbom
docker build -t backstage:latest .
```

### 5. Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f k8s/backstage/namespace.yaml

# Create secrets
kubectl create secret generic backstage-secrets \
  --from-literal=GITHUB_TOKEN='your-github-token' \
  -n backstage

# Deploy Backstage
kubectl apply -f k8s/backstage/configmap.yaml
kubectl apply -f k8s/backstage/deployment.yaml
kubectl apply -f k8s/backstage/service.yaml
```

### 6. Access Backstage

```bash
# Port forward to access locally
kubectl port-forward -n backstage svc/backstage 7007:7007

# Open in browser
open http://localhost:7007
```

## Features

### Service Catalog

Navigate to the catalog to see all registered services:

- **proving-service**: Rust ZKP proof generator
- **verifier-service**: Rust ZKP proof verifier
- **ipfs-service**: Python IPFS storage service
- **blockchain-node**: Hardhat Ethereum node
- **risc0-zkvm**: Shared ZKP library

Each service shows:
- API documentation
- Kubernetes deployment status
- GitHub repository link
- Health check status
- Dependencies

### SBOM Dashboard

Access the custom SBOM dashboard at `/sbom`:

**Metrics:**
- Total SBOMs registered
- Valid vs Invalid SBOMs
- Service health status
- Recent verifications

**SBOM Table:**
- Identifier (CI run ID)
- Validation status (✅/❌)
- Timestamp
- IPFS CID
- SBOM hash
- Blockchain transaction link

**Service Health:**
- proving-service
- verifier-service
- ipfs-service
- blockchain-node

### API Explorer

Browse and test all service APIs:

1. Navigate to "APIs" in the sidebar
2. Select an API (proving-api, verifier-api, ipfs-api)
3. View OpenAPI specification
4. Try endpoints interactively
5. Generate curl commands

### Kubernetes Plugin

View live Kubernetes resources for each service:

- Pod status and logs
- Resource usage (CPU/Memory)
- Recent deployments
- Service endpoints
- ConfigMaps and Secrets

### Software Templates

Create new SBOM-enabled services:

1. Navigate to "Create" in the sidebar
2. Select "Create SBOM-Enabled Service" template
3. Fill in the form:
   - Service name
   - Description
   - Programming language (Rust/Python/Node.js)
   - Enable ZKP proof generation
   - Enable IPFS storage
   - Enable blockchain recording
4. Click "Create"

The template will:
- Create new GitHub repository
- Generate service skeleton
- Add Dockerfile with SBOM support
- Create CI/CD workflow
- Register in Backstage catalog

## Custom Plugins

### SBOM Backend Plugin

Located in `sbom/plugins/sbom-backend/`

**Endpoints:**
- `GET /api/sbom/sboms` - List all SBOMs from blockchain
- `GET /api/sbom/sboms/:hash` - Get specific SBOM by hash
- `GET /api/sbom/proof/:sbomHash` - Retrieve proof from IPFS
- `POST /api/sbom/verify` - Verify a proof
- `GET /api/sbom/services/health` - Service health checks

**Implementation:**
- Uses ethers.js to interact with SBOMRegistry contract
- Proxies requests to microservices
- Provides aggregated data for UI

### SBOM Frontend Plugin

Located in `sbom/plugins/sbom/`

**Components:**
- `SbomPage`: Main dashboard with metrics and table
- Real-time data refresh (30s interval)
- Material-UI components
- Responsive design

## Configuration

### Adding New Services to Catalog

1. Create `catalog/<service-name>.yaml`:

```yaml
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: my-service
  description: My awesome service
  annotations:
    github.com/project-slug: tuberlin-blockchain-prototyping/my-service
    backstage.io/kubernetes-id: my-service
    backstage.io/kubernetes-namespace: sharing-sbom-system
spec:
  type: service
  lifecycle: production
  owner: team-blockchain
  system: sbom-sharing-system
```

2. Update `sbom/app-config.yaml`:

```yaml
catalog:
  locations:
    - type: file
      target: ../../catalog/my-service.yaml
```

### Customizing the Dashboard

Edit `sbom/plugins/sbom/src/components/SbomPage.tsx`:

```typescript
// Add new metrics
const avgProofTime = calculateAverageProofTime(sboms);

// Add new columns
const columns = [
  ...existingColumns,
  { title: 'Proof Time', field: 'proofTime' },
];
```

## Troubleshooting

### Backstage won't start

Check logs:
```bash
kubectl logs -n backstage deployment/backstage
```

Common issues:
- Missing GITHUB_TOKEN secret
- Database connection errors
- Plugin build failures

### Services show as unhealthy

Verify services are running:
```bash
kubectl get pods -n sharing-sbom-system
kubectl get pods -n blockchain
```

Check service URLs in ConfigMap:
```bash
kubectl describe configmap backstage-config -n backstage
```

### Catalog not loading services

1. Check GitHub token permissions (needs `repo` scope)
2. Verify catalog file paths in `app-config.yaml`
3. Force refresh: Delete and re-create Backstage pod

### SBOM Dashboard shows no data

1. Verify blockchain is running and accessible
2. Check SBOMRegistry contract has entries:
```bash
kubectl exec -n blockchain <hardhat-pod> -- npx hardhat console --network localhost
```

3. Test backend API directly:
```bash
kubectl port-forward -n backstage svc/backstage 7007:7007
curl http://localhost:7007/api/sbom/sboms
```

## Development

### Running Locally

```bash
cd sbom
yarn install
yarn dev
```

This starts:
- Frontend on http://localhost:3000
- Backend on http://localhost:7007

**Note:** You'll need to set up port forwards for the microservices:

```bash
kubectl port-forward -n sharing-sbom-system svc/proving-service 8081:8080
kubectl port-forward -n sharing-sbom-system svc/verifier-service 8082:8080
kubectl port-forward -n sharing-sbom-system svc/ipfs-service 8083:8080
kubectl port-forward -n blockchain svc/hardhat-node 8545:8545
```

Update `.env` to use localhost URLs.

### Adding New Plugins

```bash
cd sbom
yarn create-plugin --backend
# or
yarn create-plugin --frontend
```

Follow Backstage plugin development guide:
https://backstage.io/docs/plugins/create-a-plugin

## Resources

- [Backstage Documentation](https://backstage.io/docs/overview/what-is-backstage)
- [Plugin Development](https://backstage.io/docs/plugins/)
- [Software Templates](https://backstage.io/docs/features/software-templates/)
- [Kubernetes Plugin](https://backstage.io/docs/features/kubernetes/)
