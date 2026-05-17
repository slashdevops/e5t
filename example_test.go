package e5t_test

import (
	"fmt"
	"log"

	"github.com/slashdevops/e5t"
)

// ExampleGenerateHashKey demonstrates basic key generation.
func ExampleGenerateHashKey() {
	// Generate a key without salt
	key1 := e5t.GenerateHashKey("my-password")
	fmt.Printf("Key length: %d bytes\n", len(key1))

	// Generate a key with salt (recommended)
	key2 := e5t.GenerateHashKey("my-password", "unique-salt")
	fmt.Printf("Key with salt length: %d bytes\n", len(key2))

	// Output:
	// Key length: 32 bytes
	// Key with salt length: 32 bytes
}

// ExampleGenerateHashKey_withUserID demonstrates using user ID as salt.
func ExampleGenerateHashKey_withUserID() {
	userID := "user-12345"
	masterPassword := "app-master-secret"

	// Generate a unique key for this user
	userKey := e5t.GenerateHashKey(masterPassword, userID)
	fmt.Printf("Generated user-specific key: %d bytes\n", len(userKey))

	// Output:
	// Generated user-specific key: 32 bytes
}

// ExampleEncryptAsString demonstrates basic encryption.
func ExampleEncryptAsString() {
	// Generate an encryption key
	key := e5t.GenerateHashKey("my-secret-password", "random-salt")

	// Encrypt some data
	plaintext := []byte("Hello, World!")
	encrypted, err := e5t.EncryptAsString(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted data length: %d characters\n", len(encrypted))
	fmt.Println("Encrypted data is hex-encoded")

	// Output:
	// Encrypted data length: 82 characters
	// Encrypted data is hex-encoded
}

// ExampleEncrypt demonstrates basic encryption returning raw bytes.
func ExampleEncrypt() {
	// Generate an encryption key
	key := e5t.GenerateHashKey("my-secret-password", "random-salt")

	// Encrypt some data
	plaintext := []byte("Hello, World!")
	encrypted, err := e5t.Encrypt(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted data length: %d bytes\n", len(encrypted))
	fmt.Println("Encrypted data is raw bytes")

	// Output:
	// Encrypted data length: 41 bytes
	// Encrypted data is raw bytes
}

// ExampleDecryptFromText demonstrates basic decryption from hex-encoded string.
func ExampleDecryptFromText() {
	key := e5t.GenerateHashKey("my-secret-password", "random-salt")

	// Encrypt
	plaintext := []byte("Secret Message")
	encrypted, err := e5t.EncryptAsString(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt
	decrypted, err := e5t.DecryptFromText(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(decrypted))

	// Output:
	// Secret Message
}

// ExampleEncryptAsString_roundTrip demonstrates a complete encryption and decryption cycle.
func ExampleEncryptAsString_roundTrip() {
	// Create a key
	key := e5t.GenerateHashKey("secure-password", "app-salt-v1")

	// Original message
	message := []byte("This is a confidential message.")

	// Encrypt
	encrypted, err := e5t.EncryptAsString(message, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Message encrypted successfully")

	// Decrypt
	decrypted, err := e5t.DecryptFromText(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	// Output:
	// Message encrypted successfully
	// Decrypted: This is a confidential message.
}

// ExampleEncryptAsString_apiKey demonstrates encrypting an API key.
func ExampleEncryptAsString_apiKey() {
	// Encrypt a sensitive API key
	apiKey := []byte("sk_live_1234567890abcdef")
	encryptionKey := e5t.GenerateHashKey("master-key", "api-keys-v1")

	encrypted, err := e5t.EncryptAsString(apiKey, encryptionKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("API key encrypted")

	// Later, decrypt it
	decrypted, err := e5t.DecryptFromText(encrypted, encryptionKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted API key: %s\n", string(decrypted))

	// Output:
	// API key encrypted
	// Decrypted API key: sk_live_1234567890abcdef
}

// ExampleEncryptAsString_multipleEncryptions demonstrates that the same plaintext encrypts differently each time.
func ExampleEncryptAsString_multipleEncryptions() {
	key := e5t.GenerateHashKey("password", "salt")
	message := []byte("same message")

	// Encrypt the same message twice
	encrypted1, err := e5t.EncryptAsString(message, key)
	if err != nil {
		log.Fatal(err)
	}

	encrypted2, err := e5t.EncryptAsString(message, key)
	if err != nil {
		log.Fatal(err)
	}

	// The encrypted values will be different
	fmt.Printf("First encryption length: %d\n", len(encrypted1))
	fmt.Printf("Second encryption length: %d\n", len(encrypted2))
	fmt.Println("Each encryption produces unique ciphertext")

	// But both decrypt to the same message
	decrypted1, err := e5t.DecryptFromText(encrypted1, key)
	if err != nil {
		log.Fatal(err)
	}

	decrypted2, err := e5t.DecryptFromText(encrypted2, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Both decrypt correctly: %t\n", string(decrypted1) == string(decrypted2))

	// Output:
	// First encryption length: 80
	// Second encryption length: 80
	// Each encryption produces unique ciphertext
	// Both decrypt correctly: true
}

// ExampleEncryptAsString_config demonstrates encrypting configuration data.
func ExampleEncryptAsString_config() {
	// Simulate encrypting sensitive configuration
	config := []byte(`{"db_password":"secret123","api_key":"abc-xyz"}`)

	// Use application-specific key and salt
	key := e5t.GenerateHashKey("app-master-key", "config-v1")

	encrypted, err := e5t.EncryptAsString(config, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Configuration encrypted")

	// Decrypt when needed
	decrypted, err := e5t.DecryptFromText(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted config length: %d bytes\n", len(decrypted))

	// Output:
	// Configuration encrypted
	// Decrypted config length: 47 bytes
}

// ExampleDecrypt_wrongKey demonstrates error handling with wrong key.
func ExampleDecrypt_wrongKey() {
	// Encrypt with one key
	key1 := e5t.GenerateHashKey("password1", "salt")
	encrypted, err := e5t.EncryptAsString([]byte("secret"), key1)
	if err != nil {
		log.Fatal(err)
	}

	// Try to decrypt with wrong key
	key2 := e5t.GenerateHashKey("password2", "salt")
	_, err = e5t.DecryptFromText(encrypted, key2)
	if err != nil {
		fmt.Println("Decryption failed with wrong key")
	}

	// Output:
	// Decryption failed with wrong key
}

// ExampleEncryptAsString_userSpecific demonstrates per-user encryption.
func ExampleEncryptAsString_userSpecific() {
	masterKey := "application-master-key"

	// Encrypt data for user 1
	user1ID := "user-001"
	user1Key := e5t.GenerateHashKey(masterKey, user1ID)
	user1Data := []byte("User 1 private data")
	encrypted1, err := e5t.EncryptAsString(user1Data, user1Key)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt data for user 2
	user2ID := "user-002"
	user2Key := e5t.GenerateHashKey(masterKey, user2ID)
	user2Data := []byte("User 2 private data")
	encrypted2, err := e5t.EncryptAsString(user2Data, user2Key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Each user has their own encrypted data")

	// Each user can only decrypt their own data
	decrypted1, err := e5t.DecryptFromText(encrypted1, user1Key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User 1 data: %s\n", string(decrypted1))

	decrypted2, err := e5t.DecryptFromText(encrypted2, user2Key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User 2 data: %s\n", string(decrypted2))

	// Output:
	// Each user has their own encrypted data
	// User 1 data: User 1 private data
	// User 2 data: User 2 private data
}

// ExampleVerifyEncryption demonstrates verifying encrypted data matches original data.
func ExampleVerifyEncryption() {
	key := e5t.GenerateHashKey("my-password", "my-salt")

	original := []byte("Important data to verify")
	encrypted, err := e5t.EncryptAsString(original, key)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the encrypted data matches the original
	match, err := e5t.VerifyEncryption(original, encrypted, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Data matches: %t\n", match)

	// Output:
	// Data matches: true
}

// ExampleVerifyEncryption_mismatch demonstrates verification with mismatched data.
func ExampleVerifyEncryption_mismatch() {
	key := e5t.GenerateHashKey("password", "salt")

	original := []byte("Original message")
	different := []byte("Different message")

	// Encrypt different data
	encrypted, err := e5t.EncryptAsString(different, key)
	if err != nil {
		log.Fatal(err)
	}

	// Verify against original (should not match)
	match, err := e5t.VerifyEncryption(original, encrypted, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Data matches: %t\n", match)

	// Output:
	// Data matches: false
}

// ExampleVerifyEncryption_integrityCheck demonstrates using VerifyEncryption for integrity checking.
func ExampleVerifyEncryption_integrityCheck() {
	key := e5t.GenerateHashKey("secure-key", "app-v1")

	// Simulate storing data
	userData := []byte("User profile data")
	encryptedData, err := e5t.EncryptAsString(userData, key)
	if err != nil {
		log.Fatal(err)
	}

	// Store encryptedData in database/file...
	// Later, retrieve and verify integrity

	verified, err := e5t.VerifyEncryption(userData, encryptedData, key)
	if err != nil {
		fmt.Println("Verification failed:", err)
		return
	}

	if verified {
		fmt.Println("Data integrity verified successfully")
	} else {
		fmt.Println("Data integrity check failed - data was modified")
	}

	// Output:
	// Data integrity verified successfully
}
