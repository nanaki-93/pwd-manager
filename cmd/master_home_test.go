package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read start dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files in starting directory, found %d (first %q)", len(entries), entries[0].Name())
	}
}

func TestReadKeySaltRefusesSymlinkSwappedInAfterCheck(t *testing.T) {
	home := withTempHome(t)
	saltPath := filepath.Join(home, keyDerivationSaltFile)
	if err := os.WriteFile(saltPath, bytes.Repeat([]byte{1}, keyDerivationSaltLen), 0o600); err != nil {
		t.Fatalf("write salt: %v", err)
	}
	target := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(target, bytes.Repeat([]byte{9}, keyDerivationSaltLen), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	prev := openKeyFile
	openKeyFile = func(name string) (*os.File, error) {
		// Simulate the race: replace the checked file with a symlink.
		if err := os.Remove(name); err != nil {
			t.Fatalf("remove salt: %v", err)
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatalf("symlink salt: %v", err)
		}
		return prev(name)
	}
	t.Cleanup(func() { openKeyFile = prev })

	salt := make([]byte, keyDerivationSaltLen)
	_, loaded, err := readKeySalt(salt)
	if err == nil || loaded || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected swapped-in symlink to be refused, got loaded=%v err=%v", loaded, err)
	}
	if bytes.Contains(salt, []byte{9}) {
		t.Fatal("salt was read through the symlink")
	}
}

func TestWriteKeySaltRefusesSymlinkAndKeepsTarget(t *testing.T) {
	home := withTempHome(t)
	target := filepath.Join(t.TempDir(), "victim")
	orig := []byte("do not overwrite")
	if err := os.WriteFile(target, orig, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(home, keyDerivationSaltFile)); err != nil {
		t.Fatalf("symlink salt: %v", err)
	}
	if err := writeKeySalt(bytes.Repeat([]byte{2}, keyDerivationSaltLen)); err == nil {
		t.Fatal("expected writeKeySalt to refuse a symlinked salt path")
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
}
