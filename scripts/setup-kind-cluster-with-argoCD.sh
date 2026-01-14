#!/bin/bash

set -e

MISSING_TOOLS=""

if ! command -v docker &> /dev/null; then
    MISSING_TOOLS="${MISSING_TOOLS}- Docker\n"
fi

if ! command -v kind &> /dev/null; then
    MISSING_TOOLS="${MISSING_TOOLS}- Kind\n"
fi

if ! command -v kubectl &> /dev/null; then
    MISSING_TOOLS="${MISSING_TOOLS}- kubectl\n"
fi

if ! command -v git &> /dev/null; then
    MISSING_TOOLS="${MISSING_TOOLS}- git\n"
fi

if [ -n "$MISSING_TOOLS" ]; then
    echo "ERROR: Missing required tools:"
    echo -e "$MISSING_TOOLS"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "ERROR: Docker is not running"
    exit 1
fi

if kind get clusters | grep -q "sharing-sbom-system"; then
    echo "Cluster 'sharing-sbom-system' already exists"
else
    cat <<EOF | kind create cluster --name sharing-sbom-system --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30000
    hostPort: 3000
    protocol: TCP
  - containerPort: 30080
    hostPort: 8080
    protocol: TCP
EOF
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
fi

if kubectl get namespace argocd &> /dev/null; then
    echo "ArgoCD namespace already exists"
else
    kubectl create namespace argocd
    kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
    kubectl wait --for=condition=Available --timeout=300s deployment/argocd-server -n argocd
fi

ARGOCD_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d || echo "N/A")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GITOPS_REPO="${GITOPS_REPO:-tuberlin-blockchain-prototyping/sharing-sbom-system-gitops}"
GITOPS_BRANCH="${GITOPS_BRANCH:-main}"
GITOPS_REPO_URL="https://github.com/${GITOPS_REPO}.git"
TEMP_GITOPS_DIR=$(mktemp -d)

echo "Fetching ArgoCD Applications from GitOps repo..."
echo "  Repo: ${GITOPS_REPO}"
echo "  Branch: ${GITOPS_BRANCH}"

if git clone --depth 1 --branch "${GITOPS_BRANCH}" "${GITOPS_REPO_URL}" "${TEMP_GITOPS_DIR}" 2>/dev/null; then
    APPLICATIONS_FILE="${TEMP_GITOPS_DIR}/argocd/application.yaml"
    if [ -f "${APPLICATIONS_FILE}" ]; then
        echo "Applying ArgoCD Application..."
        kubectl apply -f "${APPLICATIONS_FILE}"
        echo "ArgoCD Application applied successfully"
    else
        echo "WARNING: application.yaml not found at argocd/application.yaml in GitOps repo"
        echo "Expected path: ${APPLICATIONS_FILE}"
    fi
    rm -rf "${TEMP_GITOPS_DIR}"
else
    echo "ERROR: Failed to clone GitOps repo."
    exit 1
fi

sleep 5
kubectl get application sharing-sbom-system -n argocd 2>/dev/null || echo "Application is being created"

echo ""
echo "ArgoCD UI:"
echo "  kubectl port-forward svc/argocd-server -n argocd 8080:443"
echo "  https://localhost:8080"
echo "  Username: admin"
if [ "$ARGOCD_PASSWORD" != "N/A" ]; then
    echo "  Password: $ARGOCD_PASSWORD"
fi
