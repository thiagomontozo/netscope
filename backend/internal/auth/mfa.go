package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"time"
)

type MFASetup struct {
	Secret          string   `json:"secret"`
	ProvisioningURI string   `json:"provisioningUri"`
	RecoveryCodes   []string `json:"recoveryCodes"`
}

func NewMFASetup(issuer, account string) (MFASetup, []string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return MFASetup{}, nil, err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for index := range codes {
		plain, _, err := NewOpaqueToken(9)
		if err != nil {
			return MFASetup{}, nil, err
		}
		codes[index] = plain
		hashes[index] = HashRecoveryCode(plain)
	}
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return MFASetup{Secret: secret, ProvisioningURI: "otpauth://totp/" + label + "?" + query.Encode(), RecoveryCodes: codes}, hashes, nil
}

func EncryptSecret(masterKey, secret []byte) ([]byte, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key is not configured")
	}
	key := sha256.Sum256(masterKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, secret, nil), nil
}
func DecryptSecret(masterKey, ciphertext []byte) ([]byte, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key is not configured")
	}
	key := sha256.Sum256(masterKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("encrypted secret is invalid")
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}
func VerifyTOTP(secret, code string, now time.Time) bool {
	if len(code) != 6 {
		return false
	}
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return false
	}
	for drift := -1; drift <= 1; drift++ {
		counter := uint64(now.Unix()/30 + int64(drift))
		message := make([]byte, 8)
		binary.BigEndian.PutUint64(message, counter)
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(message)
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 0x0f
		value := (uint32(sum[offset])&0x7f)<<24 | (uint32(sum[offset+1])&0xff)<<16 | (uint32(sum[offset+2])&0xff)<<8 | (uint32(sum[offset+3]) & 0xff)
		expected := []byte{byte('0' + (value/100000)%10), byte('0' + (value/10000)%10), byte('0' + (value/1000)%10), byte('0' + (value/100)%10), byte('0' + (value/10)%10), byte('0' + value%10)}
		if hmac.Equal(expected, []byte(code)) {
			return true
		}
	}
	return false
}
