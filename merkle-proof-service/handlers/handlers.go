package handlers

import (
	"net/http"

	"merkle-proof-service/service"

	"github.com/CycloneDX/cyclonedx-go"
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
	var bom cyclonedx.BOM
	if err := c.ShouldBindJSON(&bom); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	result, err := h.svc.BuildSMT(&bom, "dependency", "smt")
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, BuildResponse{
		Root:  result.Root,
		Depth: result.Depth,
	})
}

func (h *Handler) GetSMT(c *gin.Context) {
	rootHash := c.Param("root")
	
	smt, err := h.svc.GetSMT(rootHash)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "SMT not found"})
		return
	}

	c.Data(http.StatusOK, "application/json", smt)
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

	result, err := h.svc.GenerateBatchProofs(req.Root, req.PURLs, req.Compress, req.Accumulator)
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

