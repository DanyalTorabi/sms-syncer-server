package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptTOTPSecret(t *testing.T) {
	// Use a 32-byte key for AES-256
	key := "12345678901234567890123456789012"

	tests := []struct {
		name   string
		secret string
	}{
		{
			name:   "normal secret",
			secret: "JBSWY3DPEHPK3PXP",
		},
		{
			name:   "long secret",
			secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		},
		{
			name:   "short secret",
			secret: "ABC123",
		},
		{
			name:   "empty secret",
			secret: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := EncryptTOTPSecret(tt.secret, key)
			require.NoError(t, err)

			if tt.secret == "" {
				assert.Equal(t, "", encrypted, "Empty secret should return empty string")
				return
			}

			// Encrypted should be different from original
			assert.NotEqual(t, tt.secret, encrypted)

			// Encrypted should be base64
			assert.True(t, isBase64(encrypted))

			// Decrypt
			decrypted, err := DecryptTOTPSecret(encrypted, key)
			require.NoError(t, err)

			// Should match original
			assert.Equal(t, tt.secret, decrypted)
		})
	}
}

func TestEncryptTOTPSecret_DifferentNonces(t *testing.T) {
	key := "12345678901234567890123456789012"
	secret := "JBSWY3DPEHPK3PXP"

	// Encrypt same secret multiple times
	encrypted1, err1 := EncryptTOTPSecret(secret, key)
	encrypted2, err2 := EncryptTOTPSecret(secret, key)

	require.NoError(t, err1)
	require.NoError(t, err2)

	// Encrypted values should be different (due to random nonce)
	assert.NotEqual(t, encrypted1, encrypted2, "Each encryption should use a different nonce")

	// But both should decrypt to the same value
	decrypted1, _ := DecryptTOTPSecret(encrypted1, key)
	decrypted2, _ := DecryptTOTPSecret(encrypted2, key)

	assert.Equal(t, secret, decrypted1)
	assert.Equal(t, secret, decrypted2)
}

func TestEncryptTOTPSecret_InvalidKey(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	tests := []struct {
		name        string
		key         string
		expectedErr error
	}{
		{
			name:        "empty key",
			key:         "",
			expectedErr: ErrEmptyKey,
		},
		{
			name:        "short key",
			key:         "tooshort",
			expectedErr: ErrInvalidKeyLength,
		},
		{
			name:        "long key",
			key:         "123456789012345678901234567890123", // 33 bytes
			expectedErr: ErrInvalidKeyLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptTOTPSecret(secret, tt.key)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestDecryptTOTPSecret_InvalidInput(t *testing.T) {
	key := "12345678901234567890123456789012"

	tests := []struct {
		name        string
		encrypted   string
		expectedErr error
	}{
		{
			name:        "invalid base64",
			encrypted:   "not-valid-base64!!!",
			expectedErr: nil, // base64 error, not our custom error
		},
		{
			name:        "too short ciphertext",
			encrypted:   "YWJj", // "abc" in base64, too short for nonce
			expectedErr: ErrInvalidCiphertext,
		},
		{
			name:        "tampered ciphertext",
			encrypted:   "dGhpcyBpcyB0YW1wZXJlZCBjaXBoZXJ0ZXh0",
			expectedErr: nil, // GCM authentication error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptTOTPSecret(tt.encrypted, key)
			assert.Error(t, err)
			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			}
		})
	}
}

func TestDecryptTOTPSecret_WrongKey(t *testing.T) {
	key1 := "12345678901234567890123456789012"
	key2 := "abcdefghijklmnopqrstuvwxyz123456"
	secret := "JBSWY3DPEHPK3PXP"

	// Encrypt with key1
	encrypted, err := EncryptTOTPSecret(secret, key1)
	require.NoError(t, err)

	// Try to decrypt with key2
	_, err = DecryptTOTPSecret(encrypted, key2)
	assert.Error(t, err, "Should fail to decrypt with wrong key")
}

// isBase64 checks if a string is valid base64
func isBase64(s string) bool {
	// Base64 characters: A-Z, a-z, 0-9, +, /, =
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return len(s) > 0
}

func TestIsBase64Helper(t *testing.T) {
	assert.True(t, isBase64("YWJj"))
	assert.True(t, isBase64("YWJj+A=="))
	assert.False(t, isBase64("not base64!!!"))
	assert.False(t, isBase64(""))
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := "12345678901234567890123456789012"

	encrypted, err := EncryptTOTPSecret("", key)
	assert.NoError(t, err)
	assert.Equal(t, "", encrypted)

	decrypted, err := DecryptTOTPSecret("", key)
	assert.NoError(t, err)
	assert.Equal(t, "", decrypted)
}
