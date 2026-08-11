package audit

import (
	"crypto/sha256"
	"encoding/hex"
)

func Chain(previousHash string, canonicalEvent []byte) string {
	hash := sha256.New()
	hash.Write([]byte(previousHash))
	hash.Write(canonicalEvent)
	return hex.EncodeToString(hash.Sum(nil))
}
