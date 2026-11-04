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

func TestSanitizeForTerminalASCIIBoundaries(t *testing.T) {
	var printable string
	for c := byte(0x20); c <= 0x7e; c++ {
		printable += string(c)
	}
	for _, s := range []string{"", " ", "~", printable} {
		allocs := testing.AllocsPerRun(100, func() {
			if got := sanitizeForTerminal(s); got != s {
				t.Fatalf("sanitizeForTerminal(%q) = %q", s, got)
			}
		})
		if allocs != 0 {
			t.Errorf("input %q: allocations = %v, want zero", s, allocs)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"\x1f ~", `\x1f ~`},
		{" ~\x7f", ` ~\x7f`},
		{" ~\u0080", ` ~\u0080`},
	} {
		if got := sanitizeForTerminal(tc.in); got != tc.want {
			t.Errorf("sanitizeForTerminal(%q) = %q, want %q", tc.in, got, tc.want)
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
