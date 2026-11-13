package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readInstalledBinary(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestJustInstallReplacesBinaryOnlyAfterSuccessfulBuild(t *testing.T) {
	just, err := exec.LookPath("just")
	if err != nil {
		t.Skip("just is not installed")
	}
	for _, tc := range []struct {
		name     string
		override bool
		fail     bool
	}{
		{name: "default directory"},
		{name: "override directory", override: true},
		{name: "failed build preserves binary", override: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "DEV", "programs", "pwd-manager")
			if tc.override {
				dir = filepath.Join(home, "custom directory")
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(dir, "pwd-manager")
			if err := os.WriteFile(binary, []byte("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			stub := "#!/bin/sh\n[ \"$1\" = build ] && [ \"$2\" = -o ] && [ \"$4\" = . ] || exit 2\nprintf new > \"$3\"\n[ \"$FAIL_BUILD\" != 1 ]\n"
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, just, "install")
			for _, env := range os.Environ() {
				if !strings.HasPrefix(env, "INSTALL_DIR=") && !strings.HasPrefix(env, "FAIL_BUILD=") {
					cmd.Env = append(cmd.Env, env)
				}
			}
			cmd.Env = append(cmd.Env, "HOME="+home, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			if tc.override {
				cmd.Env = append(cmd.Env, "INSTALL_DIR="+dir)
			}
			if tc.fail {
				cmd.Env = append(cmd.Env, "FAIL_BUILD=1")
			}
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("just install error = %v, output: %s", err, out)
			}
			got := readInstalledBinary(t, binary)
			want := "new"
			if tc.fail {
				want = "old"
			}
			if string(got) != want {
				t.Fatalf("binary = %q, want %q", got, want)
			}
		})
	}
}
