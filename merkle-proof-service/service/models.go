package service

import "encoding/json"

type BuildResult struct {
	SMT   json.RawMessage
	Root  string
	Depth int
}

type ProofResult struct {
	Purl      string
	Value     string
	Siblings  []string
	LeafIndex string
	Bitmap    string
}

type BatchProofResult struct {
	Depth  int
	Root   string
	Proofs []ProofResult
}

