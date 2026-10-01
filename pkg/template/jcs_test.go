package template

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonical(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"sorted keys", `{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{"nested and arrays keep order", `{"z":[3,1,2],"a":{"y":true,"x":null}}`, `{"a":{"x":null,"y":true},"z":[3,1,2]}`},
		{"whitespace", "{ \"a\" :\t1 }", `{"a":1}`},
		{"escapes", `{"a":"\u0001\"\\é\n"}`, "{\"a\":\"\\u0001\\\"\\\\é\\n\"}"},
		{"utf16 key order", `{"😀":1,"￿":2}`, "{\"😀\":1,\"￿\":2}"},
		{"max integer", `{"a":9007199254740991}`, `{"a":9007199254740991}`},
		{"negative", `{"a":-5}`, `{"a":-5}`},
		{"surrogate pair", `{"a":"\ud83d\uDE00"}`, "{\"a\":\"😀\"}"},
		{"escaped backslash", `{"a":"\\ud800"}`, `{"a":"\\ud800"}`},
		{"literal U+FFFD", "{\"a\":\"\xef\xbf\xbd\"}", "{\"a\":\"\uFFFD\"}"},
		{"max depth", strings.Repeat("[", 64) + strings.Repeat("]", 64), strings.Repeat("[", 64) + strings.Repeat("]", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := decodeStrict([]byte(tc.in))
			require.NoError(t, err)
			got, err := canonical(v)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

func TestDecodeStrictRejects(t *testing.T) {
	for name, in := range map[string]string{
		"duplicate key":        `{"a":1,"a":2}`,
		"nested duplicate key": `{"a":{"b":1,"b":1}}`,
		"trailing data":        `{"a":1} {}`,
		"invalid utf8":         "{\"a\":\"\xff\"}",
		"fraction":             `{"a":1.5}`,
		"exponent":             `{"a":1e3}`,
		"too large":            `{"a":9007199254740992}`,
		"negative zero":        `{"a":-0}`,
		"lone high surrogate":  `{"a":"\ud800"}`,
		"lone low surrogate":   `{"a":"\uDC00"}`,
		"lone surrogate key":   `{"\ud800":1}`,
		"high then non-low":    `{"a":"\ud800\u0041"}`,
		"too deep":             strings.Repeat("[", 65) + strings.Repeat("]", 65),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := decodeStrict([]byte(in))
			if err == nil {
				_, err = canonical(v)
			}
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}
}
