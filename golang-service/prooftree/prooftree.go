package prooftree

import (
	"encoding/json"
	"log"
)

// ProofTree holds proof objects
type ProofTree struct {
	RTH      string    `json:"RTH,omitempty"`
	Record   string    `json:"Value,omitempty"`
	Root     ProofNode `json:"Proof,omitempty"`
	OldProof ProofNode `json:"OldProof,omitempty"`
	NewProof ProofNode `json:"NewProof,omitempty"`
}

// ProofNode represents a node in the Merkle-tree
type ProofNode struct {
	Left  *ProofNode `json:"Left,omitempty"`
	Right *ProofNode `json:"Right,omitempty"`
	Hash  string     `json:"Hash,omitempty"`
	Leaf  string     `json:"Leaf,omitempty"`
}

// UnmarshalProofTree does some unmarshaling
func UnmarshalProofTree(s string) (t *ProofTree, err error) {

	t = new(ProofTree)
	err = json.Unmarshal([]byte(s), t)
	if err != nil {
		log.Fatal(err)
	}

	return
}
