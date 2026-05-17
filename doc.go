// Package e5t provides small AES-256-GCM encryption helpers built only on the
// Go standard library.
//
// The package encrypts and decrypts byte slices with AES in Galois/Counter Mode
// (GCM). GCM is an authenticated encryption mode: successful decryption proves
// that the ciphertext, authentication tag, and nonce match the supplied key.
//
// # Encryption Format
//
// [Encrypt] returns raw bytes in this format:
//
//	nonce || ciphertext || authentication-tag
//
// [EncryptAsString] returns the same bytes encoded as hexadecimal text.
// [Decrypt] expects the raw byte format, and [DecryptFromText] expects the
// hex-encoded format.
//
// # Keys
//
// AES-256 requires a 32-byte key. [GenerateHashKey] is a convenience helper that
// returns 32 bytes by hashing a key string plus an optional salt with SHA-256:
//
//	key := e5t.GenerateHashKey("application-secret", "config-v1")
//
// For higher-risk secrets or user-entered passwords, pass a 32-byte key produced
// by a dedicated key management or password-based key derivation strategy.
//
// # Basic Usage
//
//	key := e5t.GenerateHashKey("my-secret-password", "unique-salt")
//
//	encrypted, err := e5t.EncryptAsString([]byte("sensitive data"), key)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	decrypted, err := e5t.DecryptFromText(encrypted, key)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Println(string(decrypted))
//
// # Error Handling
//
// The package returns [ErrInvalidKeySize] when a key is not exactly 32 bytes and
// [ErrCiphertextTooShort] when encrypted input is shorter than the nonce prefix.
// Use errors.Is to branch on these sentinel errors.
//
// # Dependencies
//
// e5t has zero third-party dependencies. It uses crypto/aes, crypto/cipher,
// crypto/rand, crypto/sha256, encoding/hex, and other standard library packages.
package e5t
