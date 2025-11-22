package service

import (
	"encoding/json"
	"fmt"
	"math/big"
)

type accumulator interface {
	Build(items map[string]*big.Int) ([]byte, error)
	GenerateProof(preImage string) ([][]byte, *big.Int, error)
	json.Marshaler
	json.Unmarshaler
}

func getAccumulator(name string) (accumulator, error) {
	switch name {
	case "smt":
		return newSMT(256)
	default:
		return nil, fmt.Errorf("unknown accumulator: %s", name)
	}
}

