// identity.go — ECDSA P-256 identity for constellation nodes.
//
// Adapted from apps/cogos/bep_tls.go. Simplified to just key operations:
// generate, load, sign, verify, and NodeID derivation (SHA-256 of pubkey DER).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// NodeIdentity holds the ECDSA keypair and derived node ID.
type NodeIdentity struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	NodeID     string // hex-encoded SHA-256 of DER-encoded public key
}

// GenerateIdentity creates a new ECDSA P-256 keypair and derives the NodeID.
func GenerateIdentity() (*NodeIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return identityFromKey(key)
}

// SaveIdentity writes the private key to disk as PEM.
func SaveIdentity(id *NodeIdentity, dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(id.PrivateKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	keyPath := filepath.Join(dir, "node-key.pem")
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// LoadIdentity reads an ECDSA private key from disk.
func LoadIdentity(dir string) (*NodeIdentity, error) {
	keyPath := filepath.Join(dir, "node-key.pem")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	return identityFromKey(key)
}

// identityFromKey derives NodeID from a private key.
func identityFromKey(key *ecdsa.PrivateKey) (*NodeIdentity, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	hash := sha256.Sum256(pubDER)
	return &NodeIdentity{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		NodeID:     hex.EncodeToString(hash[:]),
	}, nil
}

// Sign signs arbitrary data with the node's private key.
func (id *NodeIdentity) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, id.PrivateKey, hash[:])
}

// Verify checks a signature against a public key.
func Verify(pubKey *ecdsa.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pubKey, hash[:], signature)
}

// FormatNodeID returns a short form of the node ID (first 12 hex chars).
func FormatNodeID(nodeID string) string {
	if len(nodeID) > 12 {
		return nodeID[:12]
	}
	return nodeID
}

// PublicKeyFromDER parses an ECDSA public key from DER bytes.
func PublicKeyFromDER(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}
	return ecPub, nil
}

// MarshalPublicKey returns the DER-encoded public key.
func (id *NodeIdentity) MarshalPublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(id.PublicKey)
}
