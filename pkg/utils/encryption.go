package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var (
	// ErrInvalidCiphertext indicates the ciphertext is malformed or too short
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	// ErrEmptyKey indicates the encryption key is empty
	ErrEmptyKey = errors.New("encryption key cannot be empty")
	// ErrInvalidKeyLength indicates the encryption key is not 32 bytes
	ErrInvalidKeyLength = errors.New("encryption key must be 32 bytes for AES-256")
)

// EncryptTOTPSecret encrypts a TOTP secret using AES-256-GCM
// Returns base64-encoded ciphertext with nonce prepended
func EncryptTOTPSecret(secret, key string) (string, error) {
	if secret == "" {
		return "", nil // Don't encrypt empty strings
	}

	if key == "" {
		return "", ErrEmptyKey
	}

	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return "", ErrInvalidKeyLength
	}

	// Create AES cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create GCM mode (authenticated encryption)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, []byte(secret), nil)

	// Return base64-encoded ciphertext (nonce is prepended)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTOTPSecret decrypts a TOTP secret that was encrypted with EncryptTOTPSecret
// Expects base64-encoded ciphertext with nonce prepended
func DecryptTOTPSecret(encrypted, key string) (string, error) {
	if encrypted == "" {
		return "", nil // Don't decrypt empty strings
	}

	if key == "" {
		return "", ErrEmptyKey
	}

	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return "", ErrInvalidKeyLength
	}

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	// Create AES cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
