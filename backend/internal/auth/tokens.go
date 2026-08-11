package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func NewOpaqueToken(bytes int) (plain, digest string, err error) {
	value := make([]byte, bytes)
	if _, err = rand.Read(value); err != nil {
		return "", "", err
	}
	plain = base64.RawURLEncoding.EncodeToString(value)
	hash := sha256.Sum256([]byte(plain))
	return plain, hex.EncodeToString(hash[:]), nil
}

func HashRecoveryCode(code string) string {
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}
