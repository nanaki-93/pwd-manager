package daemon

import (
	"crypto/subtle"
	"fmt"
	"runtime"
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

var (
	clipboardClearTimeout  = DefaultClipboardClearTimeout
	writeClipboard         = clipboard.WriteAll
	readClipboard          = clipboard.ReadAll
	afterFunc              = time.AfterFunc
	clipboardOS            = runtime.GOOS
	markClipboardConcealed = func(flags []string) {}

	clipboardMu    sync.Mutex
	clipboardTimer *time.Timer
	clipboardToken uint64
)

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

	keys := make([]string, 0, len(pwdObj.SavedPasswords))
	for key := range pwdObj.SavedPasswords {
		keys = append(keys, key)
	}

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

// copyPasswordToClipboard writes pwd to the system clipboard, records
// platform-specific concealed/transient metadata hints, and schedules automatic
// clearing after clipboardClearTimeout if the clipboard still holds pwd.
func copyPasswordToClipboard(pwd string) error {
	clipboardMu.Lock()
	defer clipboardMu.Unlock()

	clipboardToken++
	token := clipboardToken
	if clipboardTimer != nil {
		clipboardTimer.Stop()
		clipboardTimer = nil
	}

	if err := writeClipboard(pwd); err != nil {
		return fmt.Errorf("write password to clipboard: %w", err)
	}
	markClipboardConcealed(ConcealedClipboardFlags(clipboardOS))

	if clipboardClearTimeout <= 0 {
		return nil
	}

	clipboardTimer = afterFunc(clipboardClearTimeout, func() {
		clipboardMu.Lock()
		defer clipboardMu.Unlock()

		if clipboardToken != token {
			return
		}

		current, err := readClipboard()
		if err != nil {
			return
		}
		if subtle.ConstantTimeCompare([]byte(current), []byte(pwd)) == 1 {
			if err := writeClipboard(""); err != nil {
				return
			}
		}
	})

	return nil
}
