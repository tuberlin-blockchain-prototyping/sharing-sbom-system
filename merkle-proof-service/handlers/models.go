package handlers

import (
	"encoding/json"

	"github.com/CycloneDX/cyclonedx-go"
)

type BuildRequest struct {
	SBOM        cyclonedx.BOM `json:"sbom"`
	Extractor   string        `json:"extractor"`
	Accumulator string        `json:"accumulator"`
}

type BuildResponse struct {
	SMT   json.RawMessage `json:"smt"`
	Root  string          `json:"root"`
	Depth int             `json:"depth"`
}

type ProveBatchRequest struct {
	SMT         json.RawMessage `json:"smt" binding:"required"`
	PURLs       []string        `json:"purls" binding:"required"`
	Compress    bool            `json:"compress"`
	Accumulator string          `json:"accumulator"`
}

type ProofOutput struct {
	Purl      string   `json:"purl"`
	Value     string   `json:"value"`
	Siblings  []string `json:"siblings"`
	LeafIndex string   `json:"leaf_index"`
	Bitmap    string   `json:"bitmap,omitempty"`
}

type ProveBatchResponse struct {
	Depth        int           `json:"depth"`
	Root         string        `json:"root"`
	MerkleProofs []ProofOutput `json:"merkle_proofs"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

