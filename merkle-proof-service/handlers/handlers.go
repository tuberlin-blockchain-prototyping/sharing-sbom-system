package handlers

import (
	"net/http"

	"merkle-proof-service/service"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *service.SMTService
}

func NewHandler(svc *service.SMTService) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) Build(c *gin.Context) {
	var req BuildRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	if req.Extractor == "" {
		req.Extractor = "dependency"
	}
	if req.Accumulator == "" {
		req.Accumulator = "smt"
	}

	result, err := h.svc.BuildSMT(&req.SBOM, req.Extractor, req.Accumulator)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, BuildResponse{
		SMT:   result.SMT,
		Root:  result.Root,
		Depth: result.Depth,
	})
}

func (h *Handler) ProveBatch(c *gin.Context) {
	var req ProveBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	if req.Accumulator == "" {
		req.Accumulator = "smt"
	}

	if len(req.PURLs) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "no purls"})
		return
	}

	result, err := h.svc.GenerateBatchProofs(req.SMT, req.PURLs, req.Compress, req.Accumulator)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	if len(result.Proofs) == 0 {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "no proofs generated"})
		return
	}

	proofs := make([]ProofOutput, len(result.Proofs))
	for i, p := range result.Proofs {
		proofs[i] = ProofOutput{
			Purl:      p.Purl,
			Value:     p.Value,
			Siblings:  p.Siblings,
			LeafIndex: p.LeafIndex,
			Bitmap:    p.Bitmap,
		}
	}

	c.JSON(http.StatusOK, ProveBatchResponse{
		Depth:        result.Depth,
		Root:         result.Root,
		MerkleProofs: proofs,
	})
}

