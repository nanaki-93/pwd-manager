package daemon

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/atotto/clipboard"
	"github.com/nanaki-93/pwd-manager/internal/model"
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
// Coverage note: hints are written natively on darwin (cgo) and windows only.
// On linux no native X11/Wayland writer exists yet, so the KDE hint
// (x-kde-passwordManagerHint) is not attached and this cap applies there too.
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
	// notifyClipboardClearFailure shows the final auto-clear outcome in a
	// visible desktop notification, since a GUI daemon user rarely sees stderr.
	notifyClipboardClearFailure = func(msg string) error {
		return zenity.Notify(msg, zenity.Title("Password Manager"))
	}

	// clipboardClearMu serializes a clear's verify-then-write against the
	// start of a new copy, so a copy cannot write its password between the
	// clear's check and its write. Lock order: clipboardClearMu, clipboardMu.
	clipboardClearMu sync.Mutex
	clipboardMu      sync.Mutex
	clipboardTimer   *time.Timer
	clipboardToken   uint64
	// clipboardStalePwds holds passwords of superseded copies that may still
	// be on the clipboard (including writes that land after a newer copy's
	// write), so the active clear also removes these values. It is emptied
	// only once a clear verified the clipboard no longer holds any of them.
	clipboardStalePwds []string
	// clipboardOwned reports whether the current token owns a clear: its copy
	// is in flight, or its clear is scheduled or retrying. clipboardActivePwd
	// is the password that clear removes.
	clipboardOwned     bool
	clipboardActivePwd string
)

// writeConcealedClipboard writes a password together with its concealment
// flags in one native clipboard operation, so clipboard monitors never see
// the secret without its hints. It is nil where no native writer exists
// (see nativeConcealedClipboardWriter); copyPasswordToClipboard then writes
// the password unhinted and caps retention at UnhintedClipboardClearTimeout.
var writeConcealedClipboard = nativeConcealedClipboardWriter()

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

// Start runs the hotkey daemon on the main thread until ctx is cancelled or
// the hotkey stops, and returns any startup failure, such as a hotkey that
// cannot be registered. A ctx already cancelled returns its error unstarted.
func Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("daemon cancelled before start: %w", err)
	}
	var err error
	mainthread.Init(func() {
		err = listenForHotkey(ctx)
	})
	return err
}

func listenForHotkey(ctx context.Context) error {
	hk := hotkey.New([]hotkey.Modifier{hotkey.ModCtrl, hotkey.ModShift}, hotkey.KeyP)
	if err := hk.Register(); err != nil {
		return fmt.Errorf("register hotkey Ctrl+Shift+P: %w", err)
	}
	defer hk.Unregister()

	fmt.Println("Daemon running. Press Ctrl+Shift+P to list passwords.")

	return serveHotkey(ctx, hk.Keydown(), showPasswordsMenu)
}

// serveHotkey calls onPress for each keydown event until ctx is cancelled
// or the event channel closes. On cancellation it first clears a password
// whose auto-clear is still pending (see clearClipboardOnShutdown), so it
// does not outlive the process; a failure to clear it is returned.
func serveHotkey(ctx context.Context, keydown <-chan hotkey.Event, onPress func()) error {
	for {
		select {
		case <-ctx.Done():
			return clearClipboardOnShutdown()
		case _, ok := <-keydown:
			if !ok {
				return nil
			}
			onPress()
		}
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

const (
	menuTitle      = "Password Manager"
	actionCopy     = "Copy password"
	actionUpdate   = "Update password"
	masterPrompt   = "Enter your master password"
	selectPrompt   = "Select a password:"
	actionPrompt   = "What do you want to do with %q?"
	newPwdPrompt   = "New password for %q"
	confirmPrompt  = "Confirm new password for %q"
	updatedMessage = "Password %q updated."
)

var (
	errEmptyNewPassword = errors.New("new password cannot be empty")
	errPasswordMismatch = errors.New("passwords do not match")
)

// askSecretFunc asks the user for a secret under prompt; a cancelled dialog
// returns an error matching zenity.ErrCanceled.
type askSecretFunc func(prompt string) (string, error)

// askSecretGUI asks for a secret in a zenity password dialog.
func askSecretGUI(prompt string) (string, error) {
	_, secret, err := zenity.Password(zenity.Title(prompt))
	return secret, err
}

func showPasswordsMenu() {
	pwdObj, err := unlockStoreGUI(askSecretGUI)
	if err != nil {
		reportMenuError(err)
		return
	}

	if len(pwdObj.SavedPasswords) == 0 {
		zenity.Info("No passwords stored.", zenity.Title(menuTitle))
		return
	}

	keys := sortedPasswordNames(pwdObj.SavedPasswords)
	selected, err := zenity.List(selectPrompt, keys, zenity.Title(menuTitle))
	if err != nil {
		return // User cancelled
	}
	pwd, ok := pwdObj.SavedPasswords[selected]
	if !ok {
		return
	}
	action, err := zenity.List(fmt.Sprintf(actionPrompt, selected), []string{actionCopy, actionUpdate}, zenity.Title(menuTitle))
	if err != nil {
		return // User cancelled
	}

	switch action {
	case actionCopy:
		if err := copyPasswordToClipboard(pwd); err != nil {
			zenity.Error(fmt.Sprintf("Failed to copy password to clipboard: %v", err), zenity.Title("Error"))
		}
	case actionUpdate:
		if err := updateSavedPassword(pwdObj, selected, askSecretGUI, utils.SaveFileErr); err != nil {
			reportMenuError(err)
			return
		}
		zenity.Info(fmt.Sprintf(updatedMessage, selected), zenity.Title(menuTitle))
	}
}

// reportMenuError shows err in an error dialog unless the user cancelled.
func reportMenuError(err error) {
	if errors.Is(err, zenity.ErrCanceled) {
		return
	}
	zenity.Error(err.Error(), zenity.Title("Error"))
}

// unlockStoreGUI asks for the master password with ask and unlocks the store,
// returning every failure as an error so the daemon keeps running.
func unlockStoreGUI(ask askSecretFunc) (model.PwdFile, error) {
	master, err := ask(masterPrompt)
	if err != nil {
		return model.PwdFile{}, fmt.Errorf("read master password: %w", err)
	}
	masterBytes := []byte(master)
	defer clear(masterBytes)
	return utils.UnlockStore(masterBytes)
}

// updateSavedPassword asks twice for a new value of the entry name and saves
// it with save. A cancelled dialog, an empty value or a mismatched
// confirmation leaves the store untouched; a failed save restores the entry.
func updateSavedPassword(pwdObj model.PwdFile, name string, ask askSecretFunc, save func(model.PwdFile, error) error) error {
	newPwd, err := ask(fmt.Sprintf(newPwdPrompt, name))
	if err != nil {
		return fmt.Errorf("read new password for %q: %w", name, err)
	}
	if newPwd == "" {
		return fmt.Errorf("update password %q: %w", name, errEmptyNewPassword)
	}
	confirm, err := ask(fmt.Sprintf(confirmPrompt, name))
	if err != nil {
		return fmt.Errorf("confirm new password for %q: %w", name, err)
	}
	if subtle.ConstantTimeCompare([]byte(newPwd), []byte(confirm)) != 1 {
		return fmt.Errorf("update password %q: %w", name, errPasswordMismatch)
	}

	prev := pwdObj.SavedPasswords[name]
	pwdObj.SavedPasswords[name] = newPwd
	if err := save(pwdObj, nil); err != nil {
		pwdObj.SavedPasswords[name] = prev
		return fmt.Errorf("save password %q: %w", name, err)
	}
	return nil
}

// copyPasswordToClipboard writes pwd to the system clipboard, together with
// platform-specific concealed/transient hints when a native concealed writer
// exists (otherwise the shorter unhinted retention is used), and schedules automatic
// clearing after clipboardClearTimeout if the clipboard still holds pwd. A
// non-positive clipboardClearTimeout is reported and replaced by
// DefaultClipboardClearTimeout, so a copied password is always cleared.
func copyPasswordToClipboard(pwd string) error {
	// Wait for an in-progress verify-and-clear so it cannot erase this copy.
	clipboardClearMu.Lock()
	clipboardMu.Lock()
	clipboardToken++
	token := clipboardToken
	// The earlier copy's clear is cancelled here (even if that copy is still
	// in flight), so its password is handed to this copy's clear.
	if clipboardOwned {
		clipboardStalePwds = append(clipboardStalePwds, clipboardActivePwd)
	}
	clipboardOwned, clipboardActivePwd = true, pwd
	if clipboardTimer != nil {
		clipboardTimer.Stop()
		clipboardTimer = nil
	}
	writeFn, flags := passwordWriterLocked()
	clipboardMu.Unlock()
	clipboardClearMu.Unlock()

	if err := writeFn(pwd); err != nil {
		return clearAfterFailedWrite(token, fmt.Errorf("write password to clipboard: %w", err))
	}

	clipboardMu.Lock()
	if clipboardToken != token {
		// A newer copy started while this write was in flight; this write may
		// have landed last, so the newer copy's clear must remove pwd too.
		adoptStaleLocked(pwd)
		clipboardMu.Unlock()
		return nil
	}
	timeout := clipboardClearTimeout
	scheduleFn := afterFunc
	report := reportClipboardClearFailure
	clipboardMu.Unlock()

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
		adoptStaleLocked(pwd)
		return nil
	}

	clipboardTimer = scheduleFn(timeout, func() {
		clearClipboardIfTokenMatches(token, pwd)
	})

	return nil
}

// clearClipboardOnShutdown runs a pending auto-clear now, synchronously: it
// stops the clear timer, invalidates the token so no scheduled or retrying
// clear runs again, and clears the clipboard only if it still holds the
// active or a stale tracked password; if the clipboard cannot be read, it
// clears it unverified and returns the read error. It holds clipboardClearMu throughout,
// so a clear already running finishes first and no new copy starts meanwhile.
func clearClipboardOnShutdown() error {
	clipboardClearMu.Lock()
	defer clipboardClearMu.Unlock()
	clipboardMu.Lock()
	if !clipboardOwned && len(clipboardStalePwds) == 0 {
		clipboardMu.Unlock()
		return nil
	}
	if clipboardTimer != nil {
		clipboardTimer.Stop()
		clipboardTimer = nil
	}
	clipboardToken++
	targets := slices.Clone(clipboardStalePwds)
	if clipboardOwned {
		targets = append(targets, clipboardActivePwd)
	}
	clipboardOwned, clipboardActivePwd, clipboardStalePwds = false, "", nil
	readFn, writeFn := readClipboard, writeClipboard
	clipboardMu.Unlock()

	current, err := readFn()
	if err != nil {
		// The clipboard cannot be verified and nothing clears it after
		// shutdown, so clear it unverified, as the timer path does. The
		// write is called directly: forceClearClipboard would take
		// clipboardClearMu again and deadlock.
		readErr := fmt.Errorf("read clipboard to clear password on shutdown: %w", err)
		if writeErr := writeFn(""); writeErr != nil {
			return errors.Join(readErr, fmt.Errorf("clear clipboard without verifying on shutdown: %w; it may still be on the clipboard", writeErr))
		}
		return readErr
	}
	if !clipboardHoldsAny(current, targets) {
		return nil
	}
	if err := writeFn(""); err != nil {
		return fmt.Errorf("clear password from clipboard on shutdown: %w; it may still be on the clipboard", err)
	}
	return nil
}

// passwordWriterLocked returns the clipboard write for a password and the
// concealment flags it attaches in the same write: the native concealed
// writer with the platform's flags when both exist, otherwise the plain
// writer and no flags. The caller holds clipboardMu.
func passwordWriterLocked() (func(string) error, []string) {
	flags := ConcealedClipboardFlags(clipboardOS)
	if writeConcealedClipboard == nil || len(flags) == 0 {
		return writeClipboard, nil
	}
	writeConcealed := writeConcealedClipboard
	return func(pwd string) error { return writeConcealed(pwd, flags) }, flags
}

// clearAfterFailedWrite runs a best-effort verified clear after writing a new
// password failed, because that copy already cancelled the earlier
// passwords' pending clear. It clears only if the clipboard still holds one
// of those passwords, leaves the work to a newer copy that has started, and
// joins any read or clear failure to writeErr so the caller learns the old
// password may remain. An earlier write still in flight schedules its own
// clear when it lands (see adoptStaleLocked).
func clearAfterFailedWrite(token uint64, writeErr error) error {
	clipboardMu.Lock()
	if clipboardToken != token {
		clipboardMu.Unlock()
		return writeErr
	}
	clipboardOwned, clipboardActivePwd = false, ""
	targets := slices.Clone(clipboardStalePwds)
	readFn := readClipboard
	clipboardMu.Unlock()
	if len(targets) == 0 {
		return writeErr
	}

	current, err := readFn()
	if err != nil {
		return errors.Join(writeErr, scheduleFailedWriteReadRetry(token, targets[len(targets)-1], err))
	}
	if !clipboardHoldsAny(current, targets) {
		dropStalePwds(token)
		return writeErr
	}
	if err := clearVerifiedClipboard(token, targets[len(targets)-1], 0); err != nil {
		return errors.Join(writeErr, fmt.Errorf("clear previous password from clipboard: %w; it may still be on the clipboard", err))
	}
	return writeErr
}

// scheduleFailedWriteReadRetry handles a failed read in clearAfterFailedWrite:
// while retries remain it restores ownership for pwd and schedules a verified
// clear after clipboardClearRetryDelays[0], whose later failures are retried
// and finally reported by clearClipboardAttempt. A newer copy that started
// meanwhile owns the stale passwords, so nothing is scheduled then.
func scheduleFailedWriteReadRetry(token uint64, pwd string, readErr error) error {
	clipboardMu.Lock()
	defer clipboardMu.Unlock()
	if clipboardToken != token || clipboardOwned {
		return fmt.Errorf("read clipboard to clear previous password: %w; it may still be on the clipboard", readErr)
	}
	if len(clipboardClearRetryDelays) == 0 {
		// Giving up: drop the plaintext passwords no clear will use any more.
		clipboardStalePwds = nil
		return fmt.Errorf("read clipboard to clear previous password (attempt 1, giving up): %w; it may still be on the clipboard", readErr)
	}
	delay := clipboardClearRetryDelays[0]
	clipboardOwned, clipboardActivePwd = true, pwd
	clipboardTimer = afterFunc(delay, func() {
		clearClipboardAttempt(token, pwd, 1)
	})
	return fmt.Errorf("read clipboard to clear previous password (attempt 1, retrying in %v): %w; it may still be on the clipboard", delay, readErr)
}

// dropStalePwds forgets the tracked stale passwords once no clear will use
// them, so their plaintext does not linger in memory. It does nothing if a
// newer copy started, since that copy now owns them. An earlier write still in
// flight re-registers its password when it lands (see adoptStaleLocked).
func dropStalePwds(token uint64) {
	clipboardMu.Lock()
	defer clipboardMu.Unlock()
	if clipboardToken == token && !clipboardOwned {
		clipboardStalePwds = nil
	}
}

// clearVerifiedClipboard clears the clipboard after the caller verified it
// holds a tracked password. It holds clipboardClearMu across the final token
// check and the write, so no new copy can start in between and have its
// password erased; if a newer copy already started, nothing is cleared. A
// failed write restores ownership for pwd and schedules a verified retry
// after clipboardClearRetryDelays[attempt] while retries remain.
func clearVerifiedClipboard(token uint64, pwd string, attempt int) error {
	clipboardClearMu.Lock()
	defer clipboardClearMu.Unlock()
	clipboardMu.Lock()
	if clipboardToken != token {
		clipboardMu.Unlock()
		return nil
	}
	clipboardOwned, clipboardActivePwd = false, ""
	writeFn := writeClipboard
	clipboardMu.Unlock()

	if err := writeFn(""); err != nil {
		return scheduleClearRetry(token, pwd, attempt, err)
	}
	// clipboardClearMu is still held, so the token cannot have changed.
	clipboardMu.Lock()
	clipboardStalePwds = nil
	clipboardMu.Unlock()
	return nil
}

// scheduleClearRetry handles a failed clearing write: while retries remain it
// restores ownership for pwd and schedules another verified clear, so a
// transient failure does not leave tracked passwords on the clipboard. The
// caller holds clipboardClearMu, so the token cannot have changed.
func scheduleClearRetry(token uint64, pwd string, attempt int, writeErr error) error {
	clipboardMu.Lock()
	defer clipboardMu.Unlock()
	if attempt >= len(clipboardClearRetryDelays) {
		// Giving up: drop the plaintext passwords no clear will use any more.
		clipboardStalePwds = nil
		return fmt.Errorf("%w (giving up after %d attempts)", writeErr, attempt+1)
	}
	delay := clipboardClearRetryDelays[attempt]
	clipboardOwned, clipboardActivePwd = true, pwd
	clipboardTimer = afterFunc(delay, func() {
		clearClipboardAttempt(token, pwd, attempt+1)
	})
	return fmt.Errorf("%w (attempt %d, retrying in %v)", writeErr, attempt+1, delay)
}

// adoptStaleLocked records pwd, whose write landed after a newer copy
// started, for the newer copy's clear. If the newer copy owns no clear any
// more (its write failed or its clear already ran), a clear is scheduled for
// pwd here with the unhinted retention, since no hint was attached for it.
// The caller holds clipboardMu.
func adoptStaleLocked(pwd string) {
	clipboardStalePwds = append(clipboardStalePwds, pwd)
	if clipboardOwned {
		return
	}
	clipboardOwned, clipboardActivePwd = true, pwd
	timeout := clipboardClearTimeout
	if timeout <= 0 {
		timeout = DefaultClipboardClearTimeout
	}
	token := clipboardToken
	clipboardTimer = afterFunc(effectiveClearTimeout(timeout, nil), func() {
		clearClipboardIfTokenMatches(token, pwd)
	})
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
// retries are exhausted the clipboard is cleared unverified and the failure is
// reported and shown in a desktop notification. The final token
// check and the clearing write run under clipboardClearMu, so no new copy can
// start between them and have its password erased.
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
	if clipboardToken != token {
		clipboardMu.Unlock()
		return
	}
	report := reportClipboardClearFailure
	if !clipboardHoldsAny(current, append([]string{pwd}, clipboardStalePwds...)) {
		// None of the tracked passwords is on the clipboard any more. A write
		// still in flight re-registers itself when it lands.
		clipboardOwned, clipboardActivePwd = false, ""
		clipboardStalePwds = nil
		clipboardMu.Unlock()
		return
	}
	clipboardMu.Unlock()

	if err := clearVerifiedClipboard(token, pwd, attempt); err != nil {
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
	// Giving up: drop the plaintext passwords no clear will use any more.
	clipboardOwned, clipboardActivePwd, clipboardStalePwds = false, "", nil
	notify := notifyClipboardClearFailure
	clipboardMu.Unlock()

	// The clipboard cannot be verified to still hold the password. Leaving it
	// would keep the secret readable indefinitely, so it is cleared anyway
	// and the user is alerted visibly, since a GUI daemon has no terminal.
	giveUpErr := fmt.Errorf("read clipboard before clearing password (attempt %d, giving up): %w", attempt+1, readErr)
	msg := "Could not verify the clipboard, so it was cleared to remove the copied password."
	cleared, clearErr := forceClearClipboard(token)
	switch {
	case clearErr != nil:
		giveUpErr = errors.Join(giveUpErr, fmt.Errorf("clear unverified clipboard: %w; the password may still be on the clipboard", clearErr))
		msg = "Could not clear the clipboard; the copied password may still be on it. Clear it manually."
	case !cleared:
		// A newer copy started and owns the clear now.
		report(giveUpErr)
		return
	}
	report(giveUpErr)
	if err := notify(msg); err != nil {
		report(fmt.Errorf("show clipboard auto-clear alert: %w", err))
	}
}

// forceClearClipboard clears the clipboard without verifying its content,
// as a last resort once reads keep failing. It holds clipboardClearMu across
// the token check and the write, so a newer copy is never erased; it reports
// cleared=false when a newer copy already started.
func forceClearClipboard(token uint64) (bool, error) {
	clipboardClearMu.Lock()
	defer clipboardClearMu.Unlock()
	clipboardMu.Lock()
	if clipboardToken != token {
		clipboardMu.Unlock()
		return false, nil
	}
	writeFn := writeClipboard
	clipboardMu.Unlock()
	if err := writeFn(""); err != nil {
		return false, err
	}
	return true, nil
}
