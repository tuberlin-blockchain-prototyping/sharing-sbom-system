package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"

	"github.com/CycloneDX/cyclonedx-go"
)

type SMTService struct{}

func NewSMTService() *SMTService {
	return &SMTService{}
}

func (s *SMTService) BuildSMT(bom *cyclonedx.BOM, extractorName, accumulatorName string) (*BuildResult, error) {
	ex, err := getExtractor(extractorName)
	if err != nil {
		return nil, err
	}

	items, err := ex.Extract(bom)
	if err != nil {
		return nil, err
	}

	acc, err := getAccumulator(accumulatorName)
	if err != nil {
		return nil, err
	}

	root, err := acc.Build(items)
	if err != nil {
		return nil, err
	}

	accData, err := json.Marshal(acc)
	if err != nil {
		return nil, err
	}

	var meta struct {
		Depth int `json:"depth"`
	}
	json.Unmarshal(accData, &meta)

	return &BuildResult{
		SMT:   json.RawMessage(accData),
		Root:  hex.EncodeToString(root),
		Depth: meta.Depth,
	}, nil
}

func (s *SMTService) GenerateBatchProofs(smtData json.RawMessage, purls []string, compress bool, accumulatorName string) (*BatchProofResult, error) {
	acc, err := getAccumulator(accumulatorName)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(smtData, acc); err != nil {
		return nil, err
	}

	var meta struct {
		Depth int    `json:"depth"`
		Root  string `json:"root"`
	}
	json.Unmarshal(smtData, &meta)

	var proofs []ProofResult

	for _, purl := range purls {
		siblings, value, err := acc.GenerateProof(purl)
		if err != nil {
			log.Printf("skipping %s: %v", purl, err)
			continue
		}

		var bitmapHex string
		nonDefaultSiblings := siblings

		if compress {
			if smtAcc, ok := acc.(*SMT); ok {
				compressed, bitmap, err := smtAcc.CompressProof(siblings)
				if err == nil {
					nonDefaultSiblings = compressed
					bitmapHex = hex.EncodeToString(packBitmapBits(bitmap))
				}
			}
		}

		siblingStrings := make([]string, len(nonDefaultSiblings))
		for i, s := range nonDefaultSiblings {
			siblingStrings[i] = hex.EncodeToString(s)
		}

		leafHash := sha256.Sum256([]byte(purl))

		proofs = append(proofs, ProofResult{
			Purl:      purl,
			Value:     value.String(),
			Siblings:  siblingStrings,
			LeafIndex: hex.EncodeToString(leafHash[:]),
			Bitmap:    bitmapHex,
		})
	}

	return &BatchProofResult{
		Depth:  meta.Depth,
		Root:   meta.Root,
		Proofs: proofs,
	}, nil
}

func packBitmapBits(bitmap []byte) []byte {
	if len(bitmap) == 0 {
		return nil
	}
	packedLen := (len(bitmap) + 7) / 8
	packed := make([]byte, packedLen)
	for d, v := range bitmap {
		if v == 0 {
			continue
		}
		byteIdx := d / 8
		bitIdx := uint(d % 8)
		packed[byteIdx] |= (1 << bitIdx)
	}
	return packed
}

