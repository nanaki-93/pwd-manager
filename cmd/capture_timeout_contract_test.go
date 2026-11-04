package cmd

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Inspect the timeout test itself: running its normal success path cannot
// detect removal of the cleanup, and deliberately blocking it would leak a
// goroutine and mutate process-wide stdout in this test process.
func TestCaptureTimeoutRegistersStdoutCleanupBeforeWorker(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "add_test.go", nil, 0)
	if err != nil {
		t.Fatalf("parse capture regression test: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "TestCaptureStdoutDrainsOutputLargerThanPipeBuffer" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("large-output capture regression test is missing")
	}
	original := ""
	cleanup := false
	for _, stmt := range body.List {
		var text bytes.Buffer
		if err := format.Node(&text, fset, stmt); err != nil {
			t.Fatalf("format capture test statement: %v", err)
		}
		if name := savedStdoutVariable(stmt); name != "" {
			original = name
		}
		compact := strings.Join(strings.Fields(text.String()), " ")
		if original != "" && compact == "t.Cleanup(func() { os.Stdout = "+original+" })" {
			cleanup = true
		}
		if _, ok := stmt.(*ast.GoStmt); ok {
			if original == "" || !cleanup {
				t.Fatal("save os.Stdout and register its restoration with t.Cleanup before starting capture")
			}
			return
		}
	}
	t.Fatal("capture worker is missing")
}

func savedStdoutVariable(stmt ast.Stmt) string {
	assignment, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return ""
	}
	selector, ok := assignment.Rhs[0].(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || pkg.Name != "os" || selector.Sel.Name != "Stdout" {
		return ""
	}
	name, ok := assignment.Lhs[0].(*ast.Ident)
	if !ok {
		return ""
	}
	return name.Name
}
