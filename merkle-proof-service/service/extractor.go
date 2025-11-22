package service

import (
	"fmt"
	"log"
	"math/big"

	"github.com/CycloneDX/cyclonedx-go"
)

type extractor interface {
	Extract(bom *cyclonedx.BOM) (map[string]*big.Int, error)
}

func getExtractor(name string) (extractor, error) {
	switch name {
	case "dependency":
		return &dependencyExtractor{}, nil
	default:
		return nil, fmt.Errorf("unknown extractor: %s", name)
	}
}

type dependencyExtractor struct{}

var valueOne = big.NewInt(1)

func (e *dependencyExtractor) Extract(bom *cyclonedx.BOM) (map[string]*big.Int, error) {
	items := make(map[string]*big.Int)

	if bom.Components == nil {
		return items, nil
	}

	for _, comp := range *bom.Components {
		if comp.PackageURL == "" {
			log.Printf("component %s has no PURL, skipping", comp.Name)
			continue
		}
		items[comp.PackageURL] = valueOne
	}

	return items, nil
}

