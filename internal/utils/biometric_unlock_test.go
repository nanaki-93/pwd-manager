package utils

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/biometric"
	"github.com/nanaki-93/pwd-manager/internal/model"
)

type biometricUnlockCase struct {
	name                   string
	marker                 bool
	authErr                error
	secret                 string
	wantPrompt, wantDelete bool
}

func TestBiometricUnlockAndFallback(t *testing.T) {
	for _, tc := range []biometricUnlockCase{
		{name: "not enabled", wantPrompt: true},
		{name: "success", marker: true, secret: "right"},
		{name: "cancelled", marker: true, authErr: biometric.ErrCanceled, wantPrompt: true},
		{name: "unavailable", marker: true, authErr: biometric.ErrUnavailable, wantPrompt: true},
		{name: "stale", marker: true, secret: "wrong", wantPrompt: true, wantDelete: true},
	} {
		t.Run(tc.name, func(t *testing.T) { checkBiometricUnlock(t, tc) })
	}
}

func checkBiometricUnlock(t *testing.T, tc biometricUnlockCase) {
	home := withTempHome(t)
	writeV3Store(t, []byte("right"), model.PwdFile{SavedPasswords: map[string]string{"site": "value"}})
	marker := filepath.Join(home, BiometricMarkerName)
	if tc.marker {
		if err := os.WriteFile(marker, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded := []byte(tc.secret)
	prompted := []byte("right")
	calls, loads, prompts, deletes := 0, 0, 0, 0
	bio := biometrics{
		authenticate: func(string) error { calls++; return tc.authErr },
		loadSecret:   func() ([]byte, error) { loads++; return loaded, nil },
		deleteSecret: func() error { deletes++; return nil },
	}
	var notices bytes.Buffer
	got, err := unlockSecret(bio, func() []byte { prompts++; return prompted }, &notices)
	if err != nil || got.SavedPasswords["site"] != "value" {
		t.Fatalf("unlock = %+v, %v", got, err)
	}
	if (prompts == 1) != tc.wantPrompt || (deletes == 1) != tc.wantDelete {
		t.Fatalf("prompts=%d deletes=%d", prompts, deletes)
	}
	checkBiometricEffects(t, tc, marker, calls, loads, prompts, loaded, prompted, notices.Len())
}

func checkBiometricEffects(t *testing.T, tc biometricUnlockCase, marker string, calls, loads, prompts int, loaded, prompted []byte, notices int) {
	if !tc.marker && (calls != 0 || loads != 0 || notices != 0) {
		t.Fatal("opt-out invoked biometrics or emitted notice")
	}
	if tc.authErr != nil && loads != 0 {
		t.Fatal("loaded secret after failed authentication")
	}
	if loads == 1 && !bytes.Equal(loaded, make([]byte, len(loaded))) {
		t.Fatal("keychain buffer not wiped")
	}
	if prompts == 1 && !bytes.Equal(prompted, make([]byte, len(prompted))) {
		t.Fatal("prompt buffer not wiped")
	}
	if tc.wantDelete {
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale marker remains: %v", err)
		}
	}
}

func TestBiometricRefreshFailureDisablesOptIn(t *testing.T) {
	home := withTempHome(t)
	marker := filepath.Join(home, BiometricMarkerName)
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	saveErr := errors.New("keychain failure")
	deleted := false
	bio := biometrics{
		saveSecret: func(secret []byte) error {
			if string(secret) != "new" {
				t.Fatal("wrong rotated password")
			}
			return saveErr
		},
		deleteSecret: func() error { deleted = true; return nil },
	}
	if err := refreshBiometricSecret(bio, []byte("new")); !errors.Is(err, saveErr) {
		t.Fatalf("refresh error = %v", err)
	}
	if !deleted {
		t.Fatal("stale secret was not deleted")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker remains: %v", err)
	}
}
