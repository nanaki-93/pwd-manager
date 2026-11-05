package utils

import (
	"bytes"
	"context"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKDFOverrideNotInProductionSources guards against an exported hook that
// lets importing packages replace kdf with a forgeable function.
func TestKDFOverrideNotInProductionSources(t *testing.T) {
	fset := token.NewFileSet()
	notTest := func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }
	pkgs, err := parser.ParseDir(fset, ".", notTest, 0)
	if err != nil {
		t.Fatalf("parse package sources: %v", err)
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if obj := file.Scope.Lookup("SetKDFForTesting"); obj != nil {
				t.Fatalf("%s declares SetKDFForTesting; keep KDF overrides in _test.go files", name)
			}
		}
	}
}

// Compile a real importing binary: test-package exports must not leak into it.
func TestKDFOverrideUnavailableToProductionCaller(t *testing.T) {
	// Keep the probe inside the module so Go's internal-package rule permits
	// the import; an unrelated import error must not count as protection.
	dir, err := os.MkdirTemp(".", "kdf-production-probe-")
	if err != nil {
		t.Fatalf("create production probe: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove production probe: %v", err)
		}
	})
	source := filepath.Join(dir, "main.go")
	for _, tc := range []struct {
		name      string
		body      string
		wantError string
	}{
		{"existing hash callers still build", "_, _ = utils.HashMasterPassword(nil); _ = utils.VerifyMasterPassword(\"\", nil)", ""},
		{"replacement hook is unavailable", "_ = utils.SetKDFForTesting", "undefined: utils.SetKDFForTesting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := "package main\nimport \"github.com/nanaki-93/pwd-manager/internal/utils\"\nfunc main() {" + tc.body + "}\n"
			if err := os.WriteFile(source, []byte(program), 0600); err != nil {
				t.Fatalf("write production probe: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(t.TempDir(), "probe"), source)
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("production build timed out: %v", ctx.Err())
			}
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("build existing production caller: %v\n%s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), tc.wantError) {
				t.Fatalf("build hook caller: error=%v, output=%s; want %q", err, output, tc.wantError)
			}
		})
	}
}

func TestKDFOverrideHashAndEncryptionParameters(t *testing.T) {
	password := []byte("override-master-secret")
	calls := 0
	var hashSalt []byte
	restore := SetKDFForTesting(func(p, salt []byte, iter, keyLen int) []byte {
		calls++
		if !bytes.Equal(p, password) || iter != pbkdf2Iter || keyLen != derivedKeySize {
			t.Fatalf("incorrect KDF arguments: iterations=%d, keyLen=%d", iter, keyLen)
		}
		if calls == 1 {
			hashSalt = append([]byte(nil), salt...)
			if len(salt) != saltSize {
				t.Fatalf("hash salt length = %d, want %d", len(salt), saltSize)
			}
		} else if calls == 2 && !bytes.Equal(salt, hashSalt) {
			t.Fatal("verification did not use recorded hash salt")
		} else if calls == 3 && !bytes.Equal(salt, []byte("store-salt:enc-v2")) {
			t.Fatal("encryption derivation lost domain separation")
		}
		return bytes.Repeat([]byte{0x61}, keyLen)
	})
	t.Cleanup(restore)
	stored, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hashIterations(t, stored) != pbkdf2Iter || !VerifyMasterPassword(stored, password) {
		t.Fatal("hash/verify failed to share override with unscaled recorded iterations")
	}
	got := deriveEncryptionKey(password, []byte("store-salt"), pbkdf2Iter)
	if !bytes.Equal(got, bytes.Repeat([]byte{0x61}, derivedKeySize)) || calls != 3 {
		t.Fatalf("encryption did not use override: calls=%d", calls)
	}
}

func TestKDFOverrideNestedRestore(t *testing.T) {
	password, salt := []byte("restore-secret"), []byte("restore-salt")
	original := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize)
	restoreOuter := SetKDFForTesting(func(_, _ []byte, _, n int) []byte {
		return bytes.Repeat([]byte{0x21}, n)
	})
	t.Cleanup(restoreOuter)
	restoreInner := SetKDFForTesting(func(_, _ []byte, _, n int) []byte {
		return bytes.Repeat([]byte{0x42}, n)
	})
	t.Cleanup(restoreInner)
	if got := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize); !bytes.Equal(got, bytes.Repeat([]byte{0x42}, derivedKeySize)) {
		t.Fatal("inner override inactive")
	}
	restoreInner()
	if got := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize); !bytes.Equal(got, bytes.Repeat([]byte{0x21}, derivedKeySize)) {
		t.Fatal("inner restore did not reinstate outer override")
	}
	restoreOuter()
	if got := kdf(password, salt, legacyPBKDF2Iter, derivedKeySize); !bytes.Equal(got, original) {
		t.Fatal("outer restore did not reinstate original KDF")
	}
}
