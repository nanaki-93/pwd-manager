package cmd

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
)

func TestCaptureStdoutEmptyAndRepeatedCalls(t *testing.T) {
	original := os.Stdout
	for i := 0; i < 3; i++ {
		called := false
		got := captureStdout(t, func() { called = true })
		if !called || got != "" {
			t.Fatalf("capture %d: callback called=%v, output=%q", i, called, got)
		}
		if os.Stdout != original {
			t.Fatalf("capture %d did not restore stdout", i)
		}
	}
}

func TestCaptureStdoutRestoresStdoutOnGoexit(t *testing.T) {
	original := os.Stdout
	done := make(chan struct{})
	go func() {
		defer close(done)
		captureStdout(t, func() { runtime.Goexit() })
	}()
	<-done
	if os.Stdout != original {
		t.Fatal("captureStdout did not restore stdout after Goexit")
	}
}

func TestSeedExecAddVaultClearsMasterKeyAfterCleanup(t *testing.T) {
	withTempHome(t)
	t.Run("seed", func(t *testing.T) {
		seedExecAddVault(t, "valid-master-pass", nil)
		if _, err := utils.GetPwdObj(); err != nil {
			t.Fatalf("seeded vault is not readable: %v", err)
		}
	})
	// Saving requires an active key. The child test's cleanup must clear it,
	// even though its HOME and working directory have also been restored.
	err := utils.SaveFileErr(model.PwdFile{}, nil)
	if !errors.Is(err, utils.ErrMasterKeyRequired) {
		t.Fatalf("expected cleared session key after seed cleanup, got %v", err)
	}
}
