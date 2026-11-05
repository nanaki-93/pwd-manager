package cmd

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

// countingReader counts the bytes its caller pulls from the wrapped reader.
type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func TestReadPwdNameBoundsInput(t *testing.T) {
	const oversized = 1 << 20
	src := &countingReader{r: strings.NewReader(strings.Repeat("a", oversized) + "\n")}

	_, err := readPwdName(src)
	if !errors.Is(err, errInvalidPwdName) {
		t.Fatalf("expected errInvalidPwdName for oversized line, got %v", err)
	}
	// One bufio fill past the bound is allowed; the whole line is not.
	if limit := maxPwdNameLen*utf8.UTFMax + len("\r\n") + 4096; src.read > limit {
		t.Fatalf("readPwdName consumed %d bytes, want at most %d", src.read, limit)
	}
}

func TestReadPwdNameAcceptsLongestNameAndKeepsRest(t *testing.T) {
	longest := strings.Repeat("😀", maxPwdNameLen)
	reader := bufio.NewReader(strings.NewReader(longest + "\r\ny\n"))

	name, err := readPwdName(reader)
	if err != nil {
		t.Fatalf("expected longest valid name to be accepted, got %v", err)
	}
	if name != longest {
		t.Fatalf("expected name of %d runes, got %q", maxPwdNameLen, name)
	}
	rest, err := reader.ReadString('\n')
	if err != nil || rest != "y\n" {
		t.Fatalf("expected remaining input %q, got %q (err %v)", "y\n", rest, err)
	}
}
