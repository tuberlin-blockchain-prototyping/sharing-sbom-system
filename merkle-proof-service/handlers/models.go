package handlers

import (
	"encoding/json"
)

type ProveBatchRequest struct {
	Root        string   `json:"root" binding:"required"`
	PURLs       []string `json:"purls" binding:"required"`
	Compress    bool     `json:"compress"`
	Accumulator string   `json:"accumulator"`
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

type StoreSMTRequest struct {
	RootHash string          `json:"root_hash" binding:"required"`
	SMTData  json.RawMessage `json:"smt_data" binding:"required"`
}

type StoreSMTResponse struct {
	RootHash string `json:"root_hash"`
	Stored   bool   `json:"stored"`
	Message  string `json:"message"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
