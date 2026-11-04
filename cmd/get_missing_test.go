package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestHandleGetOutputEmptyStoreReturnsError(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()
	clipboardWriteAll = func(string) error {
		t.Fatalf("clipboard must not be touched when the store is empty")
		return nil
	}

	want := "get password 'github': the password store is empty; add one with 'pwd-manager add'"
	for _, saved := range []map[string]string{nil, {}} {
		var err error
		out := captureStdout(t, func() {
			err = handleGetOutput("github", saved, false)
		})
		if !errors.Is(err, errEmptyPasswordStore) {
			t.Fatalf("expected errEmptyPasswordStore for empty store, got %v", err)
		}
		if err.Error() != want {
			t.Fatalf("expected %q, got %q", want, err.Error())
		}
		if out != "" {
			t.Fatalf("expected no stdout output, got %q", out)
		}
	}
}

// An empty-valued entry is present, not a failed lookup. Keep this named
// regression runnable independently for the missing-password contract.
func TestHandleGetOutputMissingReturnsError(t *testing.T) {
	stubRevealEnv(t, true, false)
	for _, saved := range []map[string]string{{"other": ""}, {}} {
		if err := handleGetOutput("missing", saved, false); err == nil {
			t.Fatal("expected lookup failure, got nil")
		}
	}
	out := captureStdout(t, func() {
		if err := handleGetOutput("", map[string]string{"": ""}, false); err != nil {
			t.Fatalf("existing empty key and value must succeed: %v", err)
		}
	})
	if out != ":" {
		t.Fatalf("existing empty entry output = %q, want colon", out)
	}
}

func TestHandleGetOutputMissingKeyReturnsError(t *testing.T) {
	err := handleGetOutput("gitlab", map[string]string{"github": "s3cr3t"}, false)
	if !errors.Is(err, errPasswordNotFound) {
		t.Fatalf("expected errPasswordNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "'gitlab'") || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("expected error naming 'gitlab' without secrets, got %q", err.Error())
	}
}
