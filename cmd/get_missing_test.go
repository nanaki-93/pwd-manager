package cmd

import "testing"

func TestHandleGetOutputEmptyStoreMessageIsComplete(t *testing.T) {
	oldWrite := clipboardWriteAll
	defer func() { clipboardWriteAll = oldWrite }()
	clipboardWriteAll = func(string) error {
		t.Fatalf("clipboard must not be touched when the store is empty")
		return nil
	}

	want := "No passwords saved with name 'github': the password store is empty. Add one with 'pwd-manager add'.\n"
	for _, saved := range []map[string]string{nil, {}} {
		var err error
		out := captureStdout(t, func() {
			err = handleGetOutput("github", saved, true)
		})
		if err != nil {
			t.Fatalf("expected nil error for empty store, got %v", err)
		}
		if out != want {
			t.Fatalf("expected %q, got %q", want, out)
		}
	}
}
