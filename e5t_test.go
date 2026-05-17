package e5t

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"testing/cryptotest"
)

func mustEncryptAsString(t *testing.T, plaintext []byte, key []byte) string {
	t.Helper()

	encrypted, err := EncryptAsString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	return encrypted
}

// TestGenerateHashKey verifies that key generation produces correct length and consistency.
func TestGenerateHashKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		salt     []string
		expected int
	}{
		{
			name:     "without salt",
			key:      "test-password",
			salt:     nil,
			expected: 32,
		},
		{
			name:     "with salt",
			key:      "test-password",
			salt:     []string{"random-salt"},
			expected: 32,
		},
		{
			name:     "empty key without salt",
			key:      "",
			salt:     nil,
			expected: 32,
		},
		{
			name:     "empty key with salt",
			key:      "",
			salt:     []string{"salt"},
			expected: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateHashKey(tt.key, tt.salt...)
			if len(result) != tt.expected {
				t.Errorf("GenerateHashKey() length = %d, want %d", len(result), tt.expected)
			}
		})
	}
}

// TestGenerateHashKeyConsistency ensures the same input produces the same key.
func TestGenerateHashKeyConsistency(t *testing.T) {
	key1 := GenerateHashKey("password", "salt")
	key2 := GenerateHashKey("password", "salt")

	if !bytes.Equal(key1, key2) {
		t.Errorf("GenerateHashKey(%q, %q) = %x and %x, want equal keys", "password", "salt", key1, key2)
	}
}

// TestGenerateHashKeyDifferentInputs ensures different inputs produce different keys.
func TestGenerateHashKeyDifferentInputs(t *testing.T) {
	key1 := GenerateHashKey("password1", "salt")
	key2 := GenerateHashKey("password2", "salt")
	key3 := GenerateHashKey("password1", "salt2")
	key4 := GenerateHashKey("password1")

	if bytes.Equal(key1, key2) {
		t.Errorf("GenerateHashKey(%q, %q) = %x, want different from GenerateHashKey(%q, %q)", "password1", "salt", key1, "password2", "salt")
	}

	if bytes.Equal(key1, key3) {
		t.Errorf("GenerateHashKey(%q, %q) = %x, want different from GenerateHashKey(%q, %q)", "password1", "salt", key1, "password1", "salt2")
	}

	if bytes.Equal(key1, key4) {
		t.Errorf("GenerateHashKey(%q, %q) = %x, want different from GenerateHashKey(%q)", "password1", "salt", key1, "password1")
	}
}

// TestEncryptDecryptRoundTrip tests basic encryption and decryption.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "empty string",
			plaintext: []byte(""),
		},
		{
			name:      "unicode text",
			plaintext: []byte("Hello 世界 🌍"),
		},
		{
			name:      "large text",
			plaintext: bytes.Repeat([]byte("a"), 10000),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
	}

	key := GenerateHashKey("test-password", "test-salt")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptAsString(tt.plaintext, key)
			if err != nil {
				t.Fatalf("EncryptAsString() error = %v", err)
			}

			if encrypted == "" {
				t.Error("EncryptAsString() returned empty string")
			}

			// Verify that the ciphertext is valid hex.
			_, err = hex.DecodeString(encrypted)
			if err != nil {
				t.Errorf("hex.DecodeString(EncryptAsString()) error = %v", err)
			}

			decrypted, err := DecryptFromText(encrypted, key)
			if err != nil {
				t.Fatalf("DecryptFromText() error = %v", err)
			}

			if !bytes.Equal(tt.plaintext, decrypted) {
				t.Errorf("DecryptFromText() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

// TestEncryptUniqueCiphertext verifies that encrypting the same plaintext twice produces different ciphertext.
func TestEncryptUniqueCiphertext(t *testing.T) {
	plaintext := []byte("test message")
	key := GenerateHashKey("password", "salt")

	encrypted1, err := EncryptAsString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	encrypted2, err := EncryptAsString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	if encrypted1 == encrypted2 {
		t.Errorf("EncryptAsString(%q, key) produced duplicate ciphertext %q, want unique ciphertext", plaintext, encrypted1)
	}

	decrypted1, err := DecryptFromText(encrypted1, key)
	if err != nil {
		t.Fatalf("DecryptFromText(encrypted1, key) error = %v", err)
	}

	decrypted2, err := DecryptFromText(encrypted2, key)
	if err != nil {
		t.Fatalf("DecryptFromText(encrypted2, key) error = %v", err)
	}

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("DecryptFromText() = %q and %q, want %q", decrypted1, decrypted2, plaintext)
	}
}

// TestEncryptWithDeterministicRandom verifies nonce generation through Go's test crypto source.
func TestEncryptWithDeterministicRandom(t *testing.T) {
	plaintext := []byte("test message")
	key := GenerateHashKey("password", "salt")

	var first []byte
	t.Run("first", func(t *testing.T) {
		cryptotest.SetGlobalRandom(t, 42)

		encrypted, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		first = encrypted
	})

	var second []byte
	t.Run("second", func(t *testing.T) {
		cryptotest.SetGlobalRandom(t, 42)

		encrypted, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		second = encrypted
	})

	if !bytes.Equal(first, second) {
		t.Errorf("Encrypt() = %x and %x, want equal ciphertexts with fixed cryptotest random", first, second)
	}

	decrypted, err := Decrypt(first, key)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

// TestEncryptInvalidKeyLength tests encryption with invalid key lengths.
func TestEncryptInvalidKeyLength(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{
			name:    "16-byte key (AES-128)",
			keyLen:  16,
			wantErr: true,
		},
		{
			name:    "24-byte key (AES-192)",
			keyLen:  24,
			wantErr: true,
		},
		{
			name:    "32-byte key (AES-256)",
			keyLen:  32,
			wantErr: false,
		},
		{
			name:    "invalid short key",
			keyLen:  8,
			wantErr: true,
		},
		{
			name:    "invalid long key",
			keyLen:  64,
			wantErr: true,
		},
		{
			name:    "empty key",
			keyLen:  0,
			wantErr: true,
		},
	}

	plaintext := []byte("test")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("rand.Read() error = %v", err)
			}

			_, err := EncryptAsString(plaintext, key)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAsString() error = %v, want error presence %v", err, tt.wantErr)
			}

			if tt.wantErr && !errors.Is(err, ErrInvalidKeySize) {
				t.Errorf("EncryptAsString() error = %v, want ErrInvalidKeySize", err)
			}
		})
	}
}

// TestDecryptInvalidKeyLength tests decryption with invalid key lengths.
func TestDecryptInvalidKeyLength(t *testing.T) {
	validKey := GenerateHashKey("password", "salt")
	encrypted := mustEncryptAsString(t, []byte("test"), validKey)

	tests := []struct {
		name   string
		keyLen int
	}{
		{"16-byte key", 16},
		{"24-byte key", 24},
		{"8-byte key", 8},
		{"64-byte key", 64},
		{"empty key", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("rand.Read() error = %v", err)
			}

			_, err := DecryptFromText(encrypted, key)
			if err == nil {
				t.Error("DecryptFromText() error = nil, want ErrInvalidKeySize")
			}

			if !errors.Is(err, ErrInvalidKeySize) {
				t.Errorf("DecryptFromText() error = %v, want ErrInvalidKeySize", err)
			}
		})
	}
}

// TestDecryptWithWrongKey verifies that decryption fails with wrong key.
func TestDecryptWithWrongKey(t *testing.T) {
	plaintext := []byte("secret message")
	key1 := GenerateHashKey("password1", "salt")
	key2 := GenerateHashKey("password2", "salt")

	encrypted, err := EncryptAsString(plaintext, key1)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	_, err = DecryptFromText(encrypted, key2)
	if err == nil {
		t.Error("DecryptFromText() error = nil, want non-nil error for wrong key")
	}
}

// TestDecryptInvalidCiphertext tests decryption of invalid ciphertext.
func TestDecryptInvalidCiphertext(t *testing.T) {
	key := GenerateHashKey("password", "salt")

	tests := []struct {
		name       string
		ciphertext string
	}{
		{
			name:       "invalid hex",
			ciphertext: "not-hex-data",
		},
		{
			name:       "empty string",
			ciphertext: "",
		},
		{
			name:       "too short",
			ciphertext: "abcd",
		},
		{
			name:       "corrupted data",
			ciphertext: hex.EncodeToString([]byte("corrupted")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptFromText(tt.ciphertext, key)
			if err == nil {
				t.Error("DecryptFromText() error = nil, want non-nil error for invalid ciphertext")
			}
		})
	}
}

// TestDecryptTamperedCiphertext verifies that tampering is detected.
func TestDecryptTamperedCiphertext(t *testing.T) {
	plaintext := []byte("important message")
	key := GenerateHashKey("password", "salt")

	encrypted, err := EncryptAsString(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	// Tamper with the encrypted data
	data, err := hex.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("hex.DecodeString(encrypted) error = %v", err)
	}

	if len(data) > 10 {
		data[len(data)-1] ^= 0x01 // Flip a bit in the last byte
	}
	tamperedHex := hex.EncodeToString(data)

	_, err = DecryptFromText(tamperedHex, key)
	if err == nil {
		t.Error("DecryptFromText() error = nil, want non-nil error for tampered ciphertext")
	}
}

// TestSentinelErrors verifies that sentinel errors can be used with errors.Is.
func TestSentinelErrors(t *testing.T) {
	t.Run("ErrInvalidKeySize in EncryptAsString", func(t *testing.T) {
		shortKey := make([]byte, 16)
		_, err := EncryptAsString([]byte("test"), shortKey)
		if !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("EncryptAsString() error = %v, want ErrInvalidKeySize", err)
		}
	})

	t.Run("ErrInvalidKeySize in DecryptFromText", func(t *testing.T) {
		shortKey := make([]byte, 16)
		_, err := DecryptFromText("abcd", shortKey)
		if !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("DecryptFromText() error = %v, want ErrInvalidKeySize", err)
		}
	})

	t.Run("ErrCiphertextTooShort", func(t *testing.T) {
		key := GenerateHashKey("password", "salt")
		_, err := DecryptFromText("abcd", key)
		if !errors.Is(err, ErrCiphertextTooShort) {
			t.Errorf("DecryptFromText() error = %v, want ErrCiphertextTooShort", err)
		}
	})
}

// BenchmarkGenerateHashKey benchmarks key generation.
func BenchmarkGenerateHashKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateHashKey("test-password", "test-salt")
	}
}

// BenchmarkGenerateHashKeyNoSalt benchmarks key generation without salt.
func BenchmarkGenerateHashKeyNoSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateHashKey("test-password")
	}
}

// BenchmarkEncrypt benchmarks encryption performance.
func BenchmarkEncrypt(b *testing.B) {
	key := GenerateHashKey("password", "salt")
	plaintext := []byte("This is a test message for benchmarking encryption performance.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptAsString(plaintext, key); err != nil {
			b.Fatalf("EncryptAsString() error = %v", err)
		}
	}
}

// BenchmarkDecrypt benchmarks decryption performance.
func BenchmarkDecrypt(b *testing.B) {
	key := GenerateHashKey("password", "salt")
	plaintext := []byte("This is a test message for benchmarking decryption performance.")
	encrypted, err := EncryptAsString(plaintext, key)
	if err != nil {
		b.Fatalf("EncryptAsString() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecryptFromText(encrypted, key); err != nil {
			b.Fatalf("DecryptFromText() error = %v", err)
		}
	}
}

// BenchmarkEncryptDecrypt benchmarks the full round-trip.
func BenchmarkEncryptDecrypt(b *testing.B) {
	key := GenerateHashKey("password", "salt")
	plaintext := []byte("This is a test message for benchmarking full round-trip performance.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := EncryptAsString(plaintext, key)
		if err != nil {
			b.Fatalf("EncryptAsString() error = %v", err)
		}

		if _, err := DecryptFromText(encrypted, key); err != nil {
			b.Fatalf("DecryptFromText() error = %v", err)
		}
	}
}

// BenchmarkEncryptLargeData benchmarks encryption of larger data.
func BenchmarkEncryptLargeData(b *testing.B) {
	key := GenerateHashKey("password", "salt")
	plaintext := bytes.Repeat([]byte("a"), 1024*100) // 100KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptAsString(plaintext, key); err != nil {
			b.Fatalf("EncryptAsString() error = %v", err)
		}
	}
}

// TestVerifyEncryption tests the VerifyEncryption function.
func TestVerifyEncryption(t *testing.T) {
	key := GenerateHashKey("password", "salt")

	tests := []struct {
		name      string
		original  []byte
		setupFunc func(t *testing.T) string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:     "matching data",
			original: []byte("test message"),
			setupFunc: func(t *testing.T) string {
				t.Helper()

				encrypted, err := EncryptAsString([]byte("test message"), key)
				if err != nil {
					t.Fatalf("EncryptAsString() error = %v", err)
				}

				return encrypted
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "non-matching data",
			original: []byte("original message"),
			setupFunc: func(t *testing.T) string {
				t.Helper()

				encrypted, err := EncryptAsString([]byte("different message"), key)
				if err != nil {
					t.Fatalf("EncryptAsString() error = %v", err)
				}

				return encrypted
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "empty data matches",
			original: []byte(""),
			setupFunc: func(t *testing.T) string {
				t.Helper()

				encrypted, err := EncryptAsString([]byte(""), key)
				if err != nil {
					t.Fatalf("EncryptAsString() error = %v", err)
				}

				return encrypted
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "unicode data",
			original: []byte("Hello 世界 🌍"),
			setupFunc: func(t *testing.T) string {
				t.Helper()

				encrypted, err := EncryptAsString([]byte("Hello 世界 🌍"), key)
				if err != nil {
					t.Fatalf("EncryptAsString() error = %v", err)
				}

				return encrypted
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "invalid encrypted data",
			original: []byte("test"),
			setupFunc: func(t *testing.T) string {
				return "invalid-hex-data"
			},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name:     "corrupted encrypted data",
			original: []byte("test"),
			setupFunc: func(t *testing.T) string {
				return "abcd1234"
			},
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := tt.setupFunc(t)
			match, err := VerifyEncryption(tt.original, encrypted, key)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyEncryption() error = %v, want error presence %v", err, tt.wantErr)
				return
			}

			if match != tt.wantMatch {
				t.Errorf("VerifyEncryption() match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

// TestVerifyEncryptionWithWrongKey tests verification with wrong key.
func TestVerifyEncryptionWithWrongKey(t *testing.T) {
	key1 := GenerateHashKey("password1", "salt")
	key2 := GenerateHashKey("password2", "salt")

	original := []byte("secret message")
	encrypted, err := EncryptAsString(original, key1)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	match, err := VerifyEncryption(original, encrypted, key2)
	if err == nil {
		t.Error("VerifyEncryption() error = nil, want non-nil error for wrong key")
	}

	if match {
		t.Error("VerifyEncryption() match = true, want false for wrong key")
	}
}

// TestVerifyEncryptionInvalidKeySize tests verification with invalid key size.
func TestVerifyEncryptionInvalidKeySize(t *testing.T) {
	validKey := GenerateHashKey("password", "salt")
	invalidKey := make([]byte, 16)

	original := []byte("test message")
	encrypted, err := EncryptAsString(original, validKey)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	match, err := VerifyEncryption(original, encrypted, invalidKey)
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("VerifyEncryption() error = %v, want ErrInvalidKeySize", err)
	}

	if match {
		t.Error("VerifyEncryption() match = true, want false for invalid key")
	}
}

// TestVerifyEncryptionLargeData tests verification with large data.
func TestVerifyEncryptionLargeData(t *testing.T) {
	key := GenerateHashKey("password", "salt")
	original := bytes.Repeat([]byte("a"), 10000)

	encrypted, err := EncryptAsString(original, key)
	if err != nil {
		t.Fatalf("EncryptAsString() error = %v", err)
	}

	match, err := VerifyEncryption(original, encrypted, key)
	if err != nil {
		t.Fatalf("VerifyEncryption() error = %v", err)
	}

	if !match {
		t.Error("VerifyEncryption() match = false, want true for matching large data")
	}
}

// BenchmarkVerifyEncryption benchmarks the verification process.
func BenchmarkVerifyEncryption(b *testing.B) {
	key := GenerateHashKey("password", "salt")
	original := []byte("This is a test message for benchmarking verification.")
	encrypted, err := EncryptAsString(original, key)
	if err != nil {
		b.Fatalf("EncryptAsString() error = %v", err)
	}

	for b.Loop() {
		if _, err := VerifyEncryption(original, encrypted, key); err != nil {
			b.Fatalf("VerifyEncryption() error = %v", err)
		}
	}
}

// TestEncryptBytes tests the Encrypt function that returns []byte.
func TestEncryptBytes(t *testing.T) {
	key := GenerateHashKey("password", "salt")
	plaintext := []byte("test message")

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("len(Encrypt()) = 0, want > 0")
	}

	// Decrypt using hex-encoded string
	hexEncrypted := hex.EncodeToString(encrypted)
	decrypted, err := DecryptFromText(hexEncrypted, key)
	if err != nil {
		t.Fatalf("DecryptFromText() error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("DecryptFromText() = %v, want %v", decrypted, plaintext)
	}
}

// TestEncryptBytesInvalidKey tests Encrypt with invalid key.
func TestEncryptBytesInvalidKey(t *testing.T) {
	shortKey := make([]byte, 16)
	_, err := Encrypt([]byte("test"), shortKey)
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("Encrypt() error = %v, want ErrInvalidKeySize", err)
	}
}

// BenchmarkEncryptBytes benchmarks the Encrypt function that returns []byte.
func BenchmarkEncryptBytes(b *testing.B) {
	key := GenerateHashKey("password", "salt")
	plaintext := []byte("This is a test message for benchmarking encryption performance.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(plaintext, key); err != nil {
			b.Fatalf("Encrypt() error = %v", err)
		}
	}
}
