package domain

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func NewID() (ID, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	if len(encoded) != 32 {
		return "", errors.New("UUID encoding failed")
	}
	return ID(encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]), nil
}
