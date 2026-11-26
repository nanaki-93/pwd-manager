package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func checkInstalledStub(t *testing.T, got []byte, failed bool) {
	t.Helper()
	if failed && string(got) != "old" {
		t.Fatalf("failed build replaced binary: %q", got)
	}
	if !failed && !strings.HasPrefix(string(got), "#!/bin/sh\n") {
		t.Fatalf("installed binary = %q, want runnable stub", got)
	}
}

func checkDaemonArgs(t *testing.T, path string, failed bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		args, err := os.ReadFile(path)
		if err == nil {
			if failed || string(args) != "daemon --restart\n" {
				t.Fatalf("daemon arguments = %q after failed build %v", args, failed)
			}
			return
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			if !failed {
				t.Fatal("installed daemon was not started")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// checkAutostartArgs checks that a successful install on macOS enabled
// starting the daemon at login, and that other installs did not.
func checkAutostartArgs(t *testing.T, path string, failed bool) {
	t.Helper()
	args, err := os.ReadFile(path)
	if !failed && runtime.GOOS == "darwin" {
		if err != nil || string(args) != "autostart enable\n" {
			t.Fatalf("autostart arguments = %q, %v; want autostart enabled", args, err)
		}
		return
	}
	if !os.IsNotExist(err) {
		t.Fatalf("autostart ran (args %q, err %v) after failed build %v on %s", args, err, failed, runtime.GOOS)
	}
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
			stub := "#!/bin/sh\n[ \"$1\" = build ] && [ \"$2\" = -o ] && [ \"$4\" = . ] || exit 2\nprintf '#!/bin/sh\\nprintf \"%%s\\\\n\" \"$*\" > \"$HOME/$1-args\"\\n' > \"$3\"\nchmod +x \"$3\"\n[ \"$FAIL_BUILD\" != 1 ]\n"
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
			checkInstalledStub(t, got, tc.fail)
			checkDaemonArgs(t, filepath.Join(home, "daemon-args"), tc.fail)
		})
	}
}
