// Package canonicaljson implements the RFC 8785 JSON Canonicalization Scheme
// used by signed NetScope protocol messages.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Canonicalize validates one I-JSON value and returns its RFC 8785 encoding.
// Numbers must be finite IEEE-754 binary64 values and must survive parsing.
func Canonicalize(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, err
	}
	if err := validateNumbers(value); err != nil {
		return nil, err
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize JSON: %w", err)
	}
	return canonical, nil
}

// Marshal canonicalizes a Go value after encoding it as JSON.
func Marshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode JSON: %w", err)
	}
	return Canonicalize(raw)
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains more than one value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func validateNumbers(value any) error {
	switch typed := value.(type) {
	case json.Number:
		if !strings.ContainsAny(string(typed), ".eE") {
			integer, err := strconv.ParseInt(string(typed), 10, 64)
			if err != nil || integer < -9007199254740991 || integer > 9007199254740991 {
				return fmt.Errorf("JSON integer %q exceeds the I-JSON interoperable range", typed)
			}
		}
		parsed, err := strconv.ParseFloat(string(typed), 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return fmt.Errorf("JSON number %q is outside the finite IEEE-754 range", typed)
		}
		if parsed == 0 && containsNonZeroDigitBeforeExponent(string(typed)) {
			return fmt.Errorf("JSON number %q underflows IEEE-754", typed)
		}
	case []any:
		for _, item := range typed {
			if err := validateNumbers(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, item := range typed {
			if err := validateNumbers(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsNonZeroDigitBeforeExponent(number string) bool {
	mantissa := strings.SplitN(number, "e", 2)[0]
	mantissa = strings.SplitN(mantissa, "E", 2)[0]
	return strings.ContainsAny(mantissa, "123456789")
}
