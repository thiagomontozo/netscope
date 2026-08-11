package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type S3Config struct {
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	PathStyle bool
	Client    *http.Client
}
type S3 struct {
	config   S3Config
	endpoint *url.URL
	client   *http.Client
}

func NewS3(config S3Config) (*S3, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" {
		return nil, errors.New("S3 endpoint must be a valid HTTPS URL")
	}
	if config.Bucket == "" || config.Region == "" || config.AccessKey == "" || config.SecretKey == "" {
		return nil, errors.New("S3 bucket, region and credentials are required")
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &S3{config: config, endpoint: endpoint, client: client}, nil
}
func (s *S3) objectURL(key string) (*url.URL, error) {
	if !safeKey.MatchString(key) {
		return nil, errors.New("invalid storage key")
	}
	result := *s.endpoint
	if s.config.PathStyle {
		result.Path = path.Join(result.Path, s.config.Bucket, key)
	} else {
		result.Host = s.config.Bucket + "." + result.Host
		result.Path = path.Join(result.Path, key)
	}
	return &result, nil
}
func (s *S3) request(ctx context.Context, method, key string, body io.Reader) (*http.Request, error) {
	target, err := s.objectURL(key)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	date := now.Format("20060102")
	timestamp := now.Format("20060102T150405Z")
	payloadHash := "UNSIGNED-PAYLOAD"
	request.Header.Set("X-Amz-Date", timestamp)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	canonicalHeaders := "host:" + target.Host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + timestamp + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{method, target.EscapedPath(), target.RawQuery, canonicalHeaders, signedHeaders, payloadHash}, "\n")
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + s.config.Region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(requestHash[:])
	dateKey := hmacSHA([]byte("AWS4"+s.config.SecretKey), date)
	regionKey := hmacSHA(dateKey, s.config.Region)
	serviceKey := hmacSHA(regionKey, "s3")
	signingKey := hmacSHA(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA(signingKey, stringToSign))
	request.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", s.config.AccessKey, scope, signedHeaders, signature))
	return request, nil
}
func hmacSHA(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
func (s *S3) Put(ctx context.Context, key string, source io.Reader) error {
	request, err := s.request(ctx, http.MethodPut, key, source)
	if err != nil {
		return err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("S3 Put returned status %d", response.StatusCode)
	}
	return nil
}
func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	request, err := s.request(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("S3 Open returned status %d", response.StatusCode)
	}
	return response.Body, nil
}
func (s *S3) Delete(ctx context.Context, key string) error {
	request, err := s.request(ctx, http.MethodDelete, key, nil)
	if err != nil {
		return err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("S3 Delete returned status %d", response.StatusCode)
	}
	return nil
}
func (s *S3) Exists(ctx context.Context, key string) (bool, error) {
	request, err := s.request(ctx, http.MethodHead, key, nil)
	if err != nil {
		return false, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("S3 Exists returned status %d", response.StatusCode)
	}
	return true, nil
}
