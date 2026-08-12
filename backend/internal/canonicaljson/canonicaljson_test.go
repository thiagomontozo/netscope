package canonicaljson

import (
	"math"
	"testing"
)

func TestCanonicalizeRFC8785Values(t *testing.T) {
	tests := []struct {
		name, input, expected string
	}{
		{"integer", `{"value":443}`, `{"value":443}`},
		{"decimal", ` { "value" : 2.500, "negative": -3.75, "exponent": 1e-6 } `, `{"exponent":0.000001,"negative":-3.75,"value":2.5}`},
		{"negative zero", `{"value":-0}`, `{"value":0}`},
		{"nested", `{"z":[3,{"b":2,"a":1}],"a":true}`, `{"a":true,"z":[3,{"a":1,"b":2}]}`},
		{"unicode UTF-16 ordering", `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}`, "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(test.input))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.expected {
				t.Fatalf("got %s, want %s", got, test.expected)
			}
		})
	}
}

func TestCanonicalizeRejectsInvalidNumbersAndJSON(t *testing.T) {
	for _, input := range []string{`{"n":NaN}`, `{"n":Infinity}`, `{"n":-Infinity}`, `{"n":1e9999}`, `{"n":1e-9999}`, `{"n":9007199254740992}`, `{"a":1,"a":2}`, `{} {}`} {
		if _, err := Canonicalize([]byte(input)); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
	if _, err := Marshal(map[string]any{"n": math.NaN()}); err == nil {
		t.Fatal("expected a programmatic NaN to be rejected")
	}
}
