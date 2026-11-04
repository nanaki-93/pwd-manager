package cmd

import (
	"bytes"
	"encoding/json"
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
