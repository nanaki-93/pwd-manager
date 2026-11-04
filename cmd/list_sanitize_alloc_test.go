package cmd

import (
	"fmt"
	"io"
	"testing"
)

func TestSanitizeForTerminalPrintableASCIIDoesNotAllocate(t *testing.T) {
	s := "github.com/user: Pa55-w0rd ~!@#$%^&*()"
	allocs := testing.AllocsPerRun(100, func() {
		if got := sanitizeForTerminal(s); got != s {
			t.Fatalf("sanitizeForTerminal(%q) = %q, want unchanged", s, got)
		}
	})
	if allocs != 0 {
		t.Fatalf("sanitizeForTerminal on printable ASCII allocated %v times per run, want 0", allocs)
	}
}

func TestSanitizeForTerminalStillEscapesAfterFastPath(t *testing.T) {
	cases := map[string]string{
		"a\x1b[31mb": `a\x1b[31mb`,
		"tab\there":  `tab\there`,
		"del\x7f":    `del\x7f`,
		"bad\xff":    `bad\xff`,
		"héllo":      "héllo",
	}
	for in, want := range cases {
		if got := sanitizeForTerminal(in); got != want {
			t.Errorf("sanitizeForTerminal(%q) = %q, want %q", in, got, want)
		}
	}
}

func BenchmarkWriteListOutput(b *testing.B) {
	entries := make(map[string]string, 10000)
	for i := 0; i < 10000; i++ {
		entries[fmt.Sprintf("service-%05d.example.com", i)] = fmt.Sprintf("password-%05d", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writeListOutput(io.Discard, entries, true); err != nil {
			b.Fatal(err)
		}
	}
}
