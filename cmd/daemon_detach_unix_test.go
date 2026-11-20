//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetachedCommandSessionAndStreams(t *testing.T) {
	in, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	child := detachedCommand("/example/binary", []string{"daemon", "--restart"}, in, out)
	if !reflect.DeepEqual(child.Args, []string{"/example/binary", "daemon", "--restart"}) {
		t.Errorf("args = %q", child.Args)
	}
	if child.SysProcAttr == nil || !child.SysProcAttr.Setsid {
		t.Error("child does not create a new session")
	}
	if child.Stdin != in || child.Stdout != out || child.Stderr != out {
		t.Error("child streams are not connected to the supplied files")
	}
}

func TestOpenDaemonLogPrivateAndAppends(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	path := filepath.Join(dir, "daemon.log")
	for _, text := range []string{"first", "second"} {
		f, err := openDaemonLog(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(text); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for path, mode := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "firstsecond" {
		t.Errorf("log = %q", data)
	}
}
