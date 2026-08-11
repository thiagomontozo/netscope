package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type StrictValidator struct{ allowed map[string]func(any) bool }

func NewStrictValidator(fields map[string]func(any) bool) StrictValidator {
	return StrictValidator{allowed: fields}
}
func (v StrictValidator) Validate(data []byte) error {
	var values map[string]any
	decoder := json.NewDecoder(bytesReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil {
		return errors.New("parameters must be a JSON object")
	}
	for name, value := range values {
		validate, ok := v.allowed[name]
		if !ok {
			return fmt.Errorf("parameter %q is not allowed", name)
		}
		if !validate(value) {
			return fmt.Errorf("parameter %q is invalid", name)
		}
	}
	return nil
}

type reader struct {
	data   []byte
	offset int
}

func bytesReader(data []byte) *reader { return &reader{data: data} }
func (r *reader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
func StringEnum(values ...string) func(any) bool {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return func(value any) bool { s, ok := value.(string); _, allowed := set[s]; return ok && allowed }
}
func NumberRange(min, max float64) func(any) bool {
	return func(value any) bool {
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && f >= min && f <= max
	}
}
func Boolean(value any) bool { _, ok := value.(bool); return ok }
func NonEmptyString(value any) bool {
	s, ok := value.(string)
	return ok && len(s) > 0 && len(s) <= 256
}
