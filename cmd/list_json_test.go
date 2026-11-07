package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestWriteListJSONOutput_MatchesMarshalIndentByteForByte(t *testing.T) {
	saved := map[string]string{
		"github":           "super-secret-1",
		"email":            "hunter2",
		"<html>&'\"":       "a<b>&c\"d\\e",
		"bad\xffutf8":      "v\xfe",
		"ünïcode ":         "line\nbreak\t\x01",
		"":                 "",
		"plain-key:no-sep": "p@ss:w0rd!",
		"b":                "plain ~!@#",
	}
	for _, show := range []bool{false, true} {
		entries := make(map[string]string, len(saved))
		for k, v := range saved {
			entries[k] = maskedPasswordPlaceholder
			if show {
				entries[k] = v
			}
		}
		want, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			t.Fatalf("marshal reference: %v", err)
		}
		var buf bytes.Buffer
		if err := writeListJSONOutput(&buf, saved, show); err != nil {
			t.Fatalf("show=%v: expected no error, got %v", show, err)
		}
		if got := buf.String(); got != string(want)+"\n" {
			t.Fatalf("show=%v: output differs:\n got %q\nwant %q", show, got, string(want)+"\n")
		}
	}
}

// maxWriteWriter records the largest single Write it receives.
type maxWriteWriter struct {
	max   int
	total int
}

func (m *maxWriteWriter) Write(p []byte) (int, error) {
	if len(p) > m.max {
		m.max = len(p)
	}
	m.total += len(p)
	return len(p), nil
}

func TestWriteListJSONOutput_StreamsLargeVaultInBoundedWrites(t *testing.T) {
	saved := make(map[string]string, 5000)
	for i := 0; i < 5000; i++ {
		saved[fmt.Sprintf("entry-%05d", i)] = strings.Repeat("s", 32)
	}
	for _, show := range []bool{false, true} {
		w := &maxWriteWriter{}
		if err := writeListJSONOutput(w, saved, show); err != nil {
			t.Fatalf("show=%v: expected no error, got %v", show, err)
		}
		if w.total < 64*1024 {
			t.Fatalf("show=%v: payload too small for the test: %d bytes", show, w.total)
		}
		if w.max > 4096 {
			t.Fatalf("show=%v: largest single write was %d bytes of %d; output is not streamed", show, w.max, w.total)
		}
	}
}

func TestWriteListJSONOutput_EscapesNonPrintableRunes(t *testing.T) {
	for _, tc := range []struct {
		name, input, escaped string
	}{
		{name: "DEL ASCII fast path", input: "a\u007fb", escaped: `a\u007fb`},
		{name: "DEL with CSI", input: "\u009b31m\u007f", escaped: `\u009b31m\u007f`},
		{name: "printable boundary", input: "~\u007f", escaped: `~\u007f`},
		{name: "C1 CSI and NEL", input: "csi\u009b31m\u0085", escaped: `csi\u009b31m\u0085`},
		{name: "printable non-ASCII kept", input: "héllo\u0080", escaped: `héllo\u0080`},
		{name: "astral non-printable", input: "astral\U000e0001", escaped: `astral\` + `udb40\` + `udc01`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, show := range []bool{false, true} {
				var buf bytes.Buffer
				if err := writeListJSONOutput(&buf, map[string]string{tc.input: tc.input}, show); err != nil {
					t.Fatalf("writeListJSONOutput: %v", err)
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

// Exercise every C1 code point in both positions, including masked keys.
func TestWriteListJSONOutput_EntireC1Range(t *testing.T) {
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
