package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
)

const HashSize = 32

type node struct {
	Left  []byte
	Right []byte
}

type SMT struct {
	depth         int
	defaultHashes [][]byte
	root          []byte
	nodes         map[string]node
	leaves        map[string]*big.Int
}

type smtItem struct {
	path  *big.Int
	value *big.Int
}

func newSMT(depth int) (*SMT, error) {
	smt := &SMT{
		depth:         depth,
		defaultHashes: make([][]byte, depth+1),
		nodes:         make(map[string]node),
		leaves:        make(map[string]*big.Int),
	}

	smt.defaultHashes[0] = hashLeaf(big.NewInt(0))

	for i := 1; i <= depth; i++ {
		smt.defaultHashes[i] = hashNode(smt.defaultHashes[i-1], smt.defaultHashes[i-1])
	}

	return smt, nil
}

func (s *SMT) Build(items map[string]*big.Int) ([]byte, error) {
	if len(items) == 0 {
		s.root = s.defaultHashes[s.depth]
		return s.root, nil
	}

	smtItems := make([]smtItem, 0, len(items))
	for preImage, value := range items {
		keyHash := sha256.Sum256([]byte(preImage))
		path := new(big.Int).SetBytes(keyHash[:])
		smtItems = append(smtItems, smtItem{path, value})
	}

	sort.Slice(smtItems, func(i, j int) bool {
		return smtItems[i].path.Cmp(smtItems[j].path) < 0
	})

	rootHash, err := s.buildRecursive(0, smtItems)
	if err != nil {
		return nil, err
	}
	s.root = rootHash

	return s.root, nil
}

func (s *SMT) buildRecursive(depth int, items []smtItem) ([]byte, error) {
	if len(items) == 0 {
		return s.defaultHashes[s.depth-depth], nil
	}

	if depth == s.depth {
		leaf := items[0]
		s.leaves[leaf.path.String()] = leaf.value
		return hashLeaf(leaf.value), nil
	}

	bitIndex := s.depth - 1 - depth

	splitIndex := sort.Search(len(items), func(i int) bool {
		return items[i].path.Bit(bitIndex) == 1
	})

	leftItems := items[:splitIndex]
	rightItems := items[splitIndex:]

	leftHash, err := s.buildRecursive(depth+1, leftItems)
	if err != nil {
		return nil, err
	}
	rightHash, err := s.buildRecursive(depth+1, rightItems)
	if err != nil {
		return nil, err
	}

	parentHash := hashNode(leftHash, rightHash)
	s.nodes[hex.EncodeToString(parentHash)] = node{Left: leftHash, Right: rightHash}

	return parentHash, nil
}

func (s *SMT) GenerateProof(preImage string) ([][]byte, *big.Int, error) {
	path, value := s.getPathAndValue(preImage)

	siblings := make([][]byte, s.depth)
	currentHash := s.root

	for d := s.depth - 1; d >= 0; d-- {
		n, isNode := s.nodes[hex.EncodeToString(currentHash)]

		if !isNode {
			if !bytes.Equal(currentHash, s.defaultHashes[d+1]) {
				return nil, nil, fmt.Errorf("tree inconsistent at depth %d", d+1)
			}
			siblings[d] = s.defaultHashes[d]
			currentHash = s.defaultHashes[d]
			continue
		}

		bit := path.Bit(d)
		if bit == 0 {
			siblings[d] = n.Right
			currentHash = n.Left
		} else {
			siblings[d] = n.Left
			currentHash = n.Right
		}
	}

	return siblings, value, nil
}

func (s *SMT) CompressProof(siblings [][]byte) ([][]byte, []byte, error) {
	if len(siblings) != s.depth {
		return nil, nil, fmt.Errorf("incorrect number of siblings")
	}

	bitmap := make([]byte, len(siblings))
	var nonDefault [][]byte

	for d := 0; d < s.depth; d++ {
		if bytes.Equal(siblings[d], s.defaultHashes[d]) {
			bitmap[d] = 0
			continue
		}
		bitmap[d] = 1
		nonDefault = append(nonDefault, siblings[d])
	}

	return nonDefault, bitmap, nil
}

func (s *SMT) getPathAndValue(preImage string) (*big.Int, *big.Int) {
	keyHash := sha256.Sum256([]byte(preImage))
	path := new(big.Int).SetBytes(keyHash[:])

	value, ok := s.leaves[path.String()]
	if !ok {
		return path, big.NewInt(0)
	}
	return path, value
}

func hashLeaf(val *big.Int) []byte {
	paddedBytes := make([]byte, HashSize)
	valBytes := val.Bytes()
	copy(paddedBytes[HashSize-len(valBytes):], valBytes)

	h := sha256.New()
	h.Write(paddedBytes)
	return h.Sum(nil)
}

func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

type smtJSON struct {
	Depth         int                    `json:"depth"`
	DefaultHashes []string               `json:"defaultHashes"`
	Root          string                 `json:"root"`
	Nodes         map[string]nodeJSON    `json:"nodes"`
	Leaves        map[string]string      `json:"leaves"`
}

type nodeJSON struct {
	Left  string `json:"left"`
	Right string `json:"right"`
}

func (s *SMT) MarshalJSON() ([]byte, error) {
	defaultHashesHex := make([]string, len(s.defaultHashes))
	for i, h := range s.defaultHashes {
		defaultHashesHex[i] = hex.EncodeToString(h)
	}

	nodes := make(map[string]nodeJSON, len(s.nodes))
	for hashKey, n := range s.nodes {
		nodes[hashKey] = nodeJSON{
			Left:  hex.EncodeToString(n.Left),
			Right: hex.EncodeToString(n.Right),
		}
	}

	leaves := make(map[string]string, len(s.leaves))
	for pathKey, val := range s.leaves {
		leaves[pathKey] = val.String()
	}

	data := smtJSON{
		Depth:         s.depth,
		DefaultHashes: defaultHashesHex,
		Root:          hex.EncodeToString(s.root),
		Nodes:         nodes,
		Leaves:        leaves,
	}

	return json.Marshal(data)
}

func (s *SMT) UnmarshalJSON(data []byte) error {
	var parsed smtJSON
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}

	s.depth = parsed.Depth

	s.defaultHashes = make([][]byte, len(parsed.DefaultHashes))
	for i, hHex := range parsed.DefaultHashes {
		h, err := hex.DecodeString(hHex)
		if err != nil {
			return err
		}
		s.defaultHashes[i] = h
	}

	root, err := hex.DecodeString(parsed.Root)
	if err != nil {
		return err
	}
	s.root = root

	s.nodes = make(map[string]node, len(parsed.Nodes))
	for hashKey, n := range parsed.Nodes {
		left, err := hex.DecodeString(n.Left)
		if err != nil {
			return err
		}
		right, err := hex.DecodeString(n.Right)
		if err != nil {
			return err
		}
		s.nodes[hashKey] = node{Left: left, Right: right}
	}

	s.leaves = make(map[string]*big.Int, len(parsed.Leaves))
	for pathKey, valStr := range parsed.Leaves {
		val, ok := new(big.Int).SetString(valStr, 10)
		if !ok {
			return fmt.Errorf("invalid big.Int: %s", valStr)
		}
		s.leaves[pathKey] = val
	}

	return nil
}

