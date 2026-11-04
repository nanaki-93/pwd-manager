package daemon

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/atotto/clipboard"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/ncruces/zenity"
	"golang.design/x/hotkey"
	"golang.design/x/hotkey/mainthread"
)

// DefaultClipboardClearTimeout defines the retention window before a copied
// password is automatically cleared from the system clipboard.
//
// Security note: Writing a password to the shared operating system clipboard
// exposes plaintext secret material to other local processes and clipboard
// managers for the duration of this timeout window. The retention window is
// kept short and paired with platform-specific concealed/transient hints to
// minimize exposure.
const DefaultClipboardClearTimeout = 10 * time.Second

// UnhintedClipboardClearTimeout caps the retention window on platforms where
// no concealed/transient clipboard hints are known (for example the BSDs,
// plan9 or any GOOS other than darwin, linux and windows). Without hints,
// clipboard history tools may persist the secret, so it is cleared sooner.
//
// Coverage note: on linux only the KDE hint (x-kde-passwordManagerHint) is
// applied; clipboard managers on other desktops may ignore it and record the
// entry in their history.
const UnhintedClipboardClearTimeout = 5 * time.Second

var (
	clipboardClearTimeout = DefaultClipboardClearTimeout
	writeClipboard        = clipboard.WriteAll
	readClipboard         = clipboard.ReadAll
	afterFunc             = time.AfterFunc
	clipboardOS           = runtime.GOOS

	// clipboardClearRetryDelays bounds the backoff used when reading the
	// clipboard fails at expiry; its length is the number of retries.
	clipboardClearRetryDelays = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second}
	// reportClipboardClearFailure surfaces clipboard clearing problems so the
	// user knows the password may still be on the clipboard.
	reportClipboardClearFailure = func(err error) {
		fmt.Fprintf(os.Stderr, "pwd-manager: clipboard auto-clear: %v\n", err)
	}

	clipboardMu    sync.Mutex
	clipboardTimer *time.Timer
	clipboardToken uint64
	// clipboardStalePwds holds passwords of copies superseded while their
	// write was in flight. Such a write can land after the active copy's
	// write, so the active clear also removes these values.
	clipboardStalePwds []string
)

// markClipboardConcealed attaches concealment hints to the clipboard entry.
// writeClipboard only receives the plain string, so no hints are attached by
// default (nil); copyPasswordToClipboard then treats the platform as unhinted
// and caps retention at UnhintedClipboardClearTimeout.
var markClipboardConcealed func(flags []string)

// ConcealedClipboardFlags returns platform-specific clipboard metadata hints
// used to mark secret entries as concealed and transient where supported.
func ConcealedClipboardFlags(goos string) []string {
	switch goos {
	case "darwin":
		return []string{
			"org.nspasteboard.ConcealedType",
			"org.nspasteboard.TransientType",
		}
	case "linux":
		return []string{
			"x-kde-passwordManagerHint=secret",
		}
	case "windows":
		return []string{
			"ExcludeClipboardContentFromMonitorProcessing",
			"CanIncludeInClipboardHistory=false",
		}
	default:
		return nil
	}
}

func Start() {
	mainthread.Init(run)
}

func run() {
	listenForHotkey()
}

func listenForHotkey() {
	hk := hotkey.New([]hotkey.Modifier{hotkey.ModCtrl, hotkey.ModShift}, hotkey.KeyP)
	err := hk.Register()
	if err != nil {
		fmt.Printf("Failed to register hotkey: %v\n", err)
		return
	}
	defer hk.Unregister()

	fmt.Println("Daemon running. Press Ctrl+Shift+P to list passwords.")

	for range hk.Keydown() {
		showPasswordsMenu()
	}
}

// sortedPasswordNames returns the names of saved passwords in ascending
// order, so the picker lists entries in a stable order on every invocation
// despite Go's randomized map iteration.
func sortedPasswordNames(saved map[string]string) []string {
	keys := make([]string, 0, len(saved))
	for key := range saved {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func showPasswordsMenu() {
	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	if err != nil {
		zenity.Error(err.Error(), zenity.Title("Error"))
		return
	}

	if len(pwdObj.SavedPasswords) == 0 {
		zenity.Info("No passwords stored.", zenity.Title("Password Manager"))
		return
	}

	keys := sortedPasswordNames(pwdObj.SavedPasswords)

	selected, err := zenity.List("Select a password to copy:", keys, zenity.Title("Password Manager"))
	if err != nil {
		return // User cancelled
	}

	if pwd, ok := pwdObj.SavedPasswords[selected]; ok {
		if err := copyPasswordToClipboard(pwd); err != nil {
			zenity.Error(fmt.Sprintf("Failed to copy password to clipboard: %v", err), zenity.Title("Error"))
		}
	}
}

// copyPasswordToClipboard writes pwd to the system clipboard, applies
// platform-specific concealed/transient metadata hints when a hint applier is
// installed (otherwise the shorter unhinted retention is used), and schedules automatic
// clearing after clipboardClearTimeout if the clipboard still holds pwd. A
// non-positive clipboardClearTimeout is reported and replaced by
// DefaultClipboardClearTimeout, so a copied password is always cleared.
func copyPasswordToClipboard(pwd string) error {
	clipboardMu.Lock()
	clipboardToken++
	token := clipboardToken
	if clipboardTimer != nil {
		clipboardTimer.Stop()
		clipboardTimer = nil
	}
	// Writes of earlier copies that land after this one are recorded again.
	clipboardStalePwds = nil
	writeFn := writeClipboard
	clipboardMu.Unlock()

	if err := writeFn(pwd); err != nil {
		return fmt.Errorf("write password to clipboard: %w", err)
	}

	clipboardMu.Lock()
	if clipboardToken != token {
		// A newer copy started while this write was in flight; this write may
		// have landed last, so the newer copy's clear must remove pwd too.
		clipboardStalePwds = append(clipboardStalePwds, pwd)
		clipboardMu.Unlock()
		return nil
	}
	markFn := markClipboardConcealed
	goos := clipboardOS
	timeout := clipboardClearTimeout
	scheduleFn := afterFunc
	report := reportClipboardClearFailure
	clipboardMu.Unlock()

	flags := ConcealedClipboardFlags(goos)
	if markFn == nil {
		// No hint can be attached, so the entry is effectively unhinted.
		flags = nil
	} else {
		markFn(flags)
	}

	if timeout <= 0 {
		// Automatic clearing cannot be disabled: a non-positive timeout is
		// treated as a misconfiguration and replaced by the safe default.
		report(fmt.Errorf("invalid clipboard clear timeout %v; using default %v", timeout, DefaultClipboardClearTimeout))
		timeout = DefaultClipboardClearTimeout
	}
	timeout = effectiveClearTimeout(timeout, flags)

	clipboardMu.Lock()
	defer clipboardMu.Unlock()
	if clipboardToken != token {
		clipboardStalePwds = append(clipboardStalePwds, pwd)
		return nil
	}

	clipboardTimer = scheduleFn(timeout, func() {
		clearClipboardIfTokenMatches(token, pwd)
	})

	return nil
}

// effectiveClearTimeout shortens a positive timeout to
// UnhintedClipboardClearTimeout when no concealment hints can be applied.
func effectiveClearTimeout(timeout time.Duration, flags []string) time.Duration {
	if len(flags) == 0 && timeout > UnhintedClipboardClearTimeout {
		return UnhintedClipboardClearTimeout
	}
	return timeout
}

func clearClipboardIfTokenMatches(token uint64, pwd string) {
	clearClipboardAttempt(token, pwd, 0)
}

// clearClipboardAttempt verifies the clipboard still holds pwd and clears it.
// A failed read is retried after clipboardClearRetryDelays[attempt]; once the
// retries are exhausted the clipboard is cleared without verification while
// the token is still active, and the failure is reported.
func clearClipboardAttempt(token uint64, pwd string, attempt int) {
	clipboardMu.Lock()
	if clipboardToken != token {
		clipboardMu.Unlock()
		return
	}
	readFn := readClipboard
	clipboardMu.Unlock()

	current, err := readFn()
	if err != nil {
		handleClearReadFailure(token, pwd, attempt, err)
		return
	}

	clipboardMu.Lock()
	targets := append([]string{pwd}, clipboardStalePwds...)
	clipboardMu.Unlock()
	if !clipboardHoldsAny(current, targets) {
		return
	}

	clipboardMu.Lock()
	if clipboardToken != token {
		clipboardMu.Unlock()
		return
	}
	writeFn := writeClipboard
	report := reportClipboardClearFailure
	clipboardMu.Unlock()

	if err := writeFn(""); err != nil {
		report(fmt.Errorf("clear password from clipboard: %w", err))
	}
}

// clipboardHoldsAny reports whether current equals one of the passwords.
func clipboardHoldsAny(current string, pwds []string) bool {
	found := false
	for _, p := range pwds {
		if subtle.ConstantTimeCompare([]byte(current), []byte(p)) == 1 {
			found = true
		}
	}
	return found
}

func handleClearReadFailure(token uint64, pwd string, attempt int, readErr error) {
	clipboardMu.Lock()
	if clipboardToken != token {
		clipboardMu.Unlock()
		return
	}
	report := reportClipboardClearFailure
	if attempt < len(clipboardClearRetryDelays) {
		delay := clipboardClearRetryDelays[attempt]
		clipboardTimer = afterFunc(delay, func() {
			clearClipboardAttempt(token, pwd, attempt+1)
		})
		clipboardMu.Unlock()
		report(fmt.Errorf("read clipboard before clearing password (attempt %d, retrying in %v): %w", attempt+1, delay, readErr))
		return
	}
	writeFn := writeClipboard
	clipboardMu.Unlock()

	err := fmt.Errorf("read clipboard before clearing password (attempt %d, giving up): %w", attempt+1, readErr)
	if werr := writeFn(""); werr != nil {
		report(errors.Join(err, fmt.Errorf("clear password from clipboard: %w; the password may still be on the clipboard", werr)))
		return
	}
	report(fmt.Errorf("%w; clipboard cleared without verification", err))
}
