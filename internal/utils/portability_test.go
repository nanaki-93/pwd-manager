/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// unixOnlySyscalls are syscall identifiers missing from GOOS=windows.
var unixOnlySyscalls = map[string]bool{"O_NOFOLLOW": true}

func TestWindowsBuildAvoidsUnixOnlySyscalls(t *testing.T) {
	ctx := build.Default
	ctx.GOOS = "windows"
	ctx.GOARCH = "amd64"
	ctx.CgoEnabled = false
	pkg, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("import package for windows: %v", err)
	}
	fset := token.NewFileSet()
	for _, name := range pkg.GoFiles {
		file, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "syscall" && unixOnlySyscalls[sel.Sel.Name] {
				t.Errorf("%s: syscall.%s is undefined on windows", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}

func TestReadSensitiveFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), sensitivePerm); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readSensitiveFile(link); err == nil {
		t.Fatalf("readSensitiveFile followed a symlink")
	}
	if got, err := readSensitiveFile(target); err != nil || string(got) != "x" {
		t.Fatalf("readSensitiveFile(target) = %q, %v", got, err)
	}
}

const sizedReadTestBytes = 1 << 20

func writeSizedReadFile(tb testing.TB) (string, []byte) {
	tb.Helper()
	want := make([]byte, sizedReadTestBytes)
	for i := range want {
		want[i] = byte(i)
	}
	path := filepath.Join(tb.TempDir(), "store")
	if err := os.WriteFile(path, want, sensitivePerm); err != nil {
		tb.Fatalf("write store: %v", err)
	}
	return path, want
}

// io.ReadAll on 1 MB grows its buffer dozens of times; a Stat-sized read
// needs only a handful of allocations (file handle, stat, one buffer).
func TestReadSensitiveFilePreallocates(t *testing.T) {
	path, want := writeSizedReadFile(t)
	got, err := readSensitiveFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("readSensitiveFile content mismatch (len %d), err %v", len(got), err)
	}
	allocs := testing.AllocsPerRun(5, func() {
		if _, err := readSensitiveFile(path); err != nil {
			t.Fatalf("readSensitiveFile: %v", err)
		}
	})
	if allocs > 12 {
		t.Fatalf("readSensitiveFile made %.0f allocations for 1 MB, want <= 12", allocs)
	}
}

func BenchmarkReadSensitiveFile(b *testing.B) {
	path, _ := writeSizedReadFile(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := readSensitiveFile(path); err != nil {
			b.Fatalf("readSensitiveFile: %v", err)
		}
	}
}
