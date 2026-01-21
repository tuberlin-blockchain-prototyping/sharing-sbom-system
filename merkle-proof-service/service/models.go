package service

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

