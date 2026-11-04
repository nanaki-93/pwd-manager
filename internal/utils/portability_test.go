/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
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
