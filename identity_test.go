// identity_test.go — Tests for ECDSA P-256 identity generation, persistence, and signing.
//
// Covers: GenerateIdentity, SaveIdentity, LoadIdentity, NodeID derivation,
// Sign/Verify, MarshalPublicKey/PublicKeyFromDER roundtrip.
package constellation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Area 1: Identity Generation
// ---------------------------------------------------------------------------

func TestGenerateIdentity_ProducesValidKeypair(t *testing.T) {
	// GenerateIdentity should return a non-nil identity with valid ECDSA P-256 key.
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}
	if id == nil {
		t.Fatal("GenerateIdentity() returned nil identity")
	}
	if id.PrivateKey == nil {
		t.Fatal("PrivateKey is nil")
	}
	if id.PublicKey == nil {
		t.Fatal("PublicKey is nil")
	}
	if id.PrivateKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", id.PrivateKey.Curve.Params().Name)
	}
	if id.NodeID == "" {
		t.Error("NodeID is empty")
	}
	// NodeID should be 64 hex chars (SHA-256 = 32 bytes = 64 hex chars).
	if len(id.NodeID) != 64 {
		t.Errorf("NodeID length = %d, want 64 hex chars", len(id.NodeID))
	}
}

func TestGenerateIdentity_DifferentCallsProduceDifferentKeys(t *testing.T) {
	// Two calls to GenerateIdentity should produce distinct keypairs.
	id1, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("first GenerateIdentity() error: %v", err)
	}
	id2, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("second GenerateIdentity() error: %v", err)
	}
	if id1.NodeID == id2.NodeID {
		t.Error("two generated identities have the same NodeID — extremely unlikely, crypto bug")
	}
	if id1.PrivateKey.D.Cmp(id2.PrivateKey.D) == 0 {
		t.Error("two generated identities have the same private key")
	}
}

func TestNodeID_DerivedFromPublicKey(t *testing.T) {
	// NodeID must equal hex(SHA-256(DER(pubkey))).
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(id.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey error: %v", err)
	}
	hash := sha256.Sum256(pubDER)
	expectedNodeID := hex.EncodeToString(hash[:])

	if id.NodeID != expectedNodeID {
		t.Errorf("NodeID = %s, want %s", id.NodeID, expectedNodeID)
	}
}

func TestSaveAndLoadIdentity_Roundtrip(t *testing.T) {
	// SaveIdentity followed by LoadIdentity should produce an equivalent identity.
	dir := t.TempDir()

	original, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	if err := SaveIdentity(original, dir); err != nil {
		t.Fatalf("SaveIdentity() error: %v", err)
	}

	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity() error: %v", err)
	}

	if loaded.NodeID != original.NodeID {
		t.Errorf("loaded NodeID = %s, want %s", loaded.NodeID, original.NodeID)
	}
	if loaded.PrivateKey.D.Cmp(original.PrivateKey.D) != 0 {
		t.Error("loaded private key does not match original")
	}
	if loaded.PublicKey.X.Cmp(original.PublicKey.X) != 0 ||
		loaded.PublicKey.Y.Cmp(original.PublicKey.Y) != 0 {
		t.Error("loaded public key does not match original")
	}
}

func TestSaveIdentity_CreatesKeyFile(t *testing.T) {
	// SaveIdentity should create a node-key.pem file with correct permissions.
	dir := t.TempDir()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	if err := SaveIdentity(id, dir); err != nil {
		t.Fatalf("SaveIdentity() error: %v", err)
	}

	keyPath := filepath.Join(dir, "node-key.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("node-key.pem not found: %v", err)
	}
	// File should not be world-readable (0600).
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		t.Errorf("node-key.pem permissions = %o, want no group/other access", mode)
	}
}

func TestLoadIdentity_MissingFile(t *testing.T) {
	// LoadIdentity on a nonexistent directory should return an error.
	_, err := LoadIdentity(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Error("expected error for missing key file, got nil")
	}
}

func TestLoadIdentity_InvalidPEM(t *testing.T) {
	// LoadIdentity with garbage PEM data should return an error.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node-key.pem")
	if err := os.WriteFile(keyPath, []byte("not a PEM file"), 0600); err != nil {
		t.Fatalf("write garbage PEM: %v", err)
	}

	_, err := LoadIdentity(dir)
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}

func TestLoadIdentity_WrongPEMType(t *testing.T) {
	// LoadIdentity with a PEM block of the wrong type should fail.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node-key.pem")
	// Write a valid-looking PEM with wrong type header.
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIBIjANBg==\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(keyPath, []byte(pem), 0600); err != nil {
		t.Fatalf("write wrong PEM type: %v", err)
	}

	_, err := LoadIdentity(dir)
	if err == nil {
		t.Error("expected error for wrong PEM type, got nil")
	}
}

// ---------------------------------------------------------------------------
// Sign and Verify
// ---------------------------------------------------------------------------

func TestSignAndVerify_ValidSignature(t *testing.T) {
	// A signature produced by Sign should be verified by Verify with the same key.
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	data := []byte("test message for signing")
	sig, err := id.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if !Verify(id.PublicKey, data, sig) {
		t.Error("Verify() returned false for valid signature")
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	// Verify should reject a mangled signature.
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	data := []byte("test message")
	sig, err := id.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	// Flip a byte in the signature.
	sig[0] ^= 0xFF

	if Verify(id.PublicKey, data, sig) {
		t.Error("Verify() returned true for tampered signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	// Verify should reject a signature checked against a different key.
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()

	data := []byte("test message")
	sig, err := id1.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if Verify(id2.PublicKey, data, sig) {
		t.Error("Verify() returned true for wrong public key")
	}
}

func TestVerify_WrongData(t *testing.T) {
	// Verify should reject a signature when the data has been changed.
	id, _ := GenerateIdentity()

	data := []byte("original data")
	sig, err := id.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if Verify(id.PublicKey, []byte("modified data"), sig) {
		t.Error("Verify() returned true for modified data")
	}
}

func TestSign_EmptyData(t *testing.T) {
	// Signing empty data should succeed and produce a verifiable signature.
	id, _ := GenerateIdentity()
	sig, err := id.Sign([]byte{})
	if err != nil {
		t.Fatalf("Sign(empty) error: %v", err)
	}
	if !Verify(id.PublicKey, []byte{}, sig) {
		t.Error("Verify(empty) returned false")
	}
}

func TestSign_LargeData(t *testing.T) {
	// Signing large data should work (SHA-256 reduces it to 32 bytes before signing).
	id, _ := GenerateIdentity()
	largeData := make([]byte, 1<<20) // 1 MiB
	sig, err := id.Sign(largeData)
	if err != nil {
		t.Fatalf("Sign(large) error: %v", err)
	}
	if !Verify(id.PublicKey, largeData, sig) {
		t.Error("Verify(large) returned false")
	}
}

// ---------------------------------------------------------------------------
// Public key serialization roundtrip
// ---------------------------------------------------------------------------

func TestMarshalPublicKey_Roundtrip(t *testing.T) {
	// MarshalPublicKey + PublicKeyFromDER should roundtrip to an equivalent key.
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	der, err := id.MarshalPublicKey()
	if err != nil {
		t.Fatalf("MarshalPublicKey() error: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("MarshalPublicKey() returned empty DER")
	}

	recovered, err := PublicKeyFromDER(der)
	if err != nil {
		t.Fatalf("PublicKeyFromDER() error: %v", err)
	}

	if recovered.X.Cmp(id.PublicKey.X) != 0 || recovered.Y.Cmp(id.PublicKey.Y) != 0 {
		t.Error("roundtripped public key does not match original")
	}
}

func TestPublicKeyFromDER_InvalidBytes(t *testing.T) {
	// PublicKeyFromDER with garbage bytes should return an error.
	_, err := PublicKeyFromDER([]byte("not a DER-encoded key"))
	if err == nil {
		t.Error("expected error for invalid DER, got nil")
	}
}

func TestPublicKeyFromDER_NonECDSAKey(t *testing.T) {
	// PublicKeyFromDER should reject a valid-but-non-ECDSA public key.
	// This exercises the type-assertion branch at identity.go:119–122.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(RSA) error: %v", err)
	}
	_, err = PublicKeyFromDER(der)
	if err == nil {
		t.Fatal("expected error for non-ECDSA (RSA) key, got nil")
	}
}

// ---------------------------------------------------------------------------
// FormatNodeID
// ---------------------------------------------------------------------------

func TestFormatNodeID_LongID(t *testing.T) {
	// FormatNodeID should truncate a 64-char NodeID to 12 chars.
	full := "a7ecf123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
	short := FormatNodeID(full)
	if len(short) != 12 {
		t.Errorf("FormatNodeID length = %d, want 12", len(short))
	}
	if short != "a7ecf1234567" {
		t.Errorf("FormatNodeID = %q, want %q", short, "a7ecf1234567")
	}
}

func TestFormatNodeID_ShortID(t *testing.T) {
	// FormatNodeID should return a short ID as-is.
	short := "abc"
	result := FormatNodeID(short)
	if result != "abc" {
		t.Errorf("FormatNodeID(%q) = %q, want %q", short, result, "abc")
	}
}

func TestFormatNodeID_ExactlyTwelve(t *testing.T) {
	id := "123456789012"
	result := FormatNodeID(id)
	if result != id {
		t.Errorf("FormatNodeID(%q) = %q, want %q", id, result, id)
	}
}

func TestFormatNodeID_Empty(t *testing.T) {
	result := FormatNodeID("")
	if result != "" {
		t.Errorf("FormatNodeID(\"\") = %q, want empty", result)
	}
}

// ---------------------------------------------------------------------------
// Table-driven: NodeID determinism from known key material
// ---------------------------------------------------------------------------

func TestIdentityFromKey_DeterministicNodeID(t *testing.T) {
	// Given the same private key, identityFromKey should always produce the same NodeID.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	id1, err := identityFromKey(key)
	if err != nil {
		t.Fatalf("first identityFromKey error: %v", err)
	}
	id2, err := identityFromKey(key)
	if err != nil {
		t.Fatalf("second identityFromKey error: %v", err)
	}

	if id1.NodeID != id2.NodeID {
		t.Errorf("same key produced different NodeIDs: %s vs %s", id1.NodeID, id2.NodeID)
	}
}
