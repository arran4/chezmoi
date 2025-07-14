package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// aesEncryptTemplateFunc encrypts plaintext using AES-GCM with the key given in
// hex and returns the ciphertext encoded with base64. The returned value can be
// passed to aesDecryptTemplateFunc to recover the original plaintext.
func (c *Config) aesEncryptTemplateFunc(keyHex, plaintext string) string {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		panic(fmt.Errorf("key hex: %w", err))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// aesDecryptTemplateFunc decrypts base64-encoded ciphertext that was produced by
// aesEncryptTemplateFunc using the key given in hex. It panics on any error.
func (c *Config) aesDecryptTemplateFunc(keyHex, ciphertextB64 string) string {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		panic(fmt.Errorf("key hex: %w", err))
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		panic(fmt.Errorf("ciphertext base64: %w", err))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	if len(data) < gcm.NonceSize() {
		panic(fmt.Errorf("ciphertext too short"))
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return string(plaintext)
}

// argon2KeyTemplateFunc derives a key of length keyLen from password and salt
// using Argon2id and returns it encoded as hex.
func (c *Config) argon2KeyTemplateFunc(password, salt string, keyLen int) string {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, uint32(keyLen))
	return hex.EncodeToString(key)
}
