package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestWriteListJSONOutputEscapesC1Controls(t *testing.T) {
	entries := map[string]string{
		"csi\u009b31mkey":  "val\u0085ue\u009b2J",
		"plain":            "héllo\u0080",
		"astral\U000e0001": "x",
	}
	var buf bytes.Buffer
	if err := writeListJSONOutput(&buf, entries, true); err != nil {
		t.Fatalf("writeListJSONOutput: %v", err)
	}
	out := buf.String()
	for _, r := range out {
		if r >= 0x80 && r <= 0x9f {
			t.Fatalf("output contains raw C1 rune %U: %q", r, out)
		}
		if r == 0xe0001 {
			t.Fatalf("output contains raw non-printable rune %U: %q", r, out)
		}
	}
	for _, want := range []string{`\u009b`, `\u0085`, `\u0080`, "héllo"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
	var got map[string]string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("round-trip got %d entries, want %d", len(got), len(entries))
	}
	for k, v := range entries {
		if got[k] != v {
			t.Errorf("round-trip %q = %q, want %q", k, got[k], v)
		}
	}
}

// Exercise every C1 code point in both positions, including masked keys.
func TestWriteListJSONOutputEntireC1Range(t *testing.T) {
	for r := rune(0x80); r <= 0x9f; r++ {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			key, value := "key"+string(r), string(r)+"value"
			for _, show := range []bool{false, true} {
				var buf bytes.Buffer
				if err := writeListJSONOutput(&buf, map[string]string{key: value}, show); err != nil {
					t.Fatal(err)
				}
				out := buf.String()
				if strings.ContainsRune(out, r) {
					t.Fatalf("show=%v: raw C1 rune in %q", show, out)
				}
				count := 1
				wantValue := maskedPasswordPlaceholder
				if show {
					count, wantValue = 2, value
				}
				if got := strings.Count(out, fmt.Sprintf(`\u%04x`, r)); got != count {
					t.Errorf("show=%v: escape count = %d, want %d", show, got, count)
				}
				var got map[string]string
				if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, map[string]string{key: wantValue}) {
					t.Errorf("show=%v: round-trip = %q", show, got)
				}
			}
		})
	}
}

func TestWriteJSONEntriesEscapesDELInKeysAndValues(t *testing.T) {
	for _, tc := range []struct {
		name, input, escaped string
	}{
		{name: "DEL ASCII fast path", input: "a\u007fb", escaped: `a\u007fb`},
		{name: "DEL with CSI", input: "\u009b31m\u007f", escaped: `\u009b31m\u007f`},
		{name: "printable boundary", input: "~\u007f", escaped: `~\u007f`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, show := range []bool{false, true} {
				var buf bytes.Buffer
				bw := bufio.NewWriter(&buf)
				entries := map[string]string{tc.input: tc.input}
				if err := writeJSONEntries(bw, []string{tc.input}, entries, show); err != nil {
					t.Fatalf("writeJSONEntries: %v", err)
				}
				if err := bw.Flush(); err != nil {
					t.Fatalf("flush: %v", err)
				}
				value, escapedValue := maskedPasswordPlaceholder, maskedPasswordPlaceholder
				if show {
					value, escapedValue = tc.input, tc.escaped
				}
				want := "{\n  \"" + tc.escaped + "\": \"" + escapedValue + "\"\n}\n"
				if got := buf.String(); got != want {
					t.Errorf("show=%v: got %q, want escaped ASCII %q", show, got, want)
				}
				var got map[string]string
				if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				if !reflect.DeepEqual(got, map[string]string{tc.input: value}) {
					t.Errorf("show=%v: round-trip = %q", show, got)
				}
			}
		})
	}
}

func TestWriteListJSONOutputPrintableMatchesMarshalIndent(t *testing.T) {
	entries := map[string]string{
		"github.com": "p<a>&ss\"\\",
		"b":          "plain ~!@#",
	}
	for _, show := range []bool{true, false} {
		want := entries
		if !show {
			want = map[string]string{}
			for k := range entries {
				want[k] = maskedPasswordPlaceholder
			}
		}
		exp, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := writeListJSONOutput(&buf, entries, show); err != nil {
			t.Fatalf("writeListJSONOutput: %v", err)
		}
		if got := buf.String(); got != string(exp)+"\n" {
			t.Errorf("show=%v: got %q, want %q", show, got, string(exp)+"\n")
		}
	}
}
