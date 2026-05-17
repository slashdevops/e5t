package e5t

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Sentinel errors for common error conditions.
var (
	// ErrInvalidKeySize is returned when a key is not exactly 32 bytes for AES-256.
	ErrInvalidKeySize = errors.New("key must be exactly 32 bytes for AES-256")

	// ErrCiphertextTooShort is returned when ciphertext is shorter than the nonce prefix.
	ErrCiphertextTooShort = errors.New("ciphertext shorter than nonce prefix")
)

const aes256KeySize = 32

// GenerateHashKey creates a deterministic 32-byte key from secret and an optional salt.
//
// It hashes secret plus the first salt value with SHA-256. This helper is useful
// for deriving stable AES-256 keys from application secrets or context strings.
// For user-entered passwords or high-risk secrets, prefer a dedicated key
// management or password-based key derivation strategy.
func GenerateHashKey(secret string, salt ...string) []byte {
	var saltValue string
	if len(salt) > 0 {
		saltValue = salt[0]
	}

	input := secret + saltValue
	hasher := sha256.Sum256([]byte(input))

	return hasher[:]
}

// EncryptAsString encrypts plaintext with AES-256-GCM and returns hex-encoded ciphertext.
//
// The decoded ciphertext is formatted as nonce followed by encrypted data and
// the GCM authentication tag. key must be exactly 32 bytes.
func EncryptAsString(plaintext []byte, key []byte) (string, error) {
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(ciphertext), nil
}

// Encrypt encrypts plaintext with AES-256-GCM and returns raw encrypted bytes.
//
// The returned bytes are formatted as nonce followed by encrypted data and the
// GCM authentication tag. key must be exactly 32 bytes.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != aes256KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := randomNonce(gcm.NonceSize())

	// Keep the nonce with the ciphertext so Decrypt can recover it.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// DecryptFromText decodes hexCiphertext and decrypts it with AES-256-GCM.
//
// hexCiphertext must be a value returned by EncryptAsString. key must be
// the same 32-byte key used for encryption.
func DecryptFromText(hexCiphertext string, key []byte) ([]byte, error) {
	if len(key) != aes256KeySize {
		return nil, ErrInvalidKeySize
	}

	data, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return nil, err
	}

	return Decrypt(data, key)
}

// Decrypt decrypts raw bytes produced by Encrypt.
//
// ciphertext must include the nonce prefix generated during encryption. key
// must be the same 32-byte key used for encryption.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != aes256KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	// Split the nonce from the actual encrypted message.
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encrypted, nil)
}

// VerifyEncryption decrypts encrypted and compares the result with original.
//
// encrypted must be a hex-encoded ciphertext returned by EncryptAsString. The
// function returns false with a nil error when decryption succeeds but the
// decrypted data does not match original.
func VerifyEncryption(original []byte, encrypted string, key []byte) (bool, error) {
	decrypted, err := DecryptFromText(encrypted, key)
	if err != nil {
		return false, err
	}

	return bytes.Equal(original, decrypted), nil
}

func randomNonce(size int) []byte {
	nonce := make([]byte, size)
	_, _ = rand.Read(nonce) // rand.Read always fills nonce and returns nil in Go 1.26.

	return nonce
}
