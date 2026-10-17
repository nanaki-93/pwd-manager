package daemon

import (
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"github.com/atotto/clipboard"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/ncruces/zenity"
	"golang.design/x/hotkey"
	"golang.design/x/hotkey/mainthread"
)

const DefaultClipboardClearTimeout = 30 * time.Second

var (
	clipboardClearTimeout = DefaultClipboardClearTimeout
	writeClipboard        = clipboard.WriteAll
	readClipboard         = clipboard.ReadAll
	afterFunc             = time.AfterFunc

	clipboardMu    sync.Mutex
	clipboardTimer *time.Timer
)

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

func copyPasswordToClipboard(pwd string) error {
	clipboardMu.Lock()
	defer clipboardMu.Unlock()

	if clipboardTimer != nil {
		clipboardTimer.Stop()
		clipboardTimer = nil
	}

	if err := writeClipboard(pwd); err != nil {
		return err
	}

	if clipboardClearTimeout <= 0 {
		return nil
	}

	clipboardTimer = afterFunc(clipboardClearTimeout, func() {
		clipboardMu.Lock()
		defer clipboardMu.Unlock()

		current, err := readClipboard()
		if err != nil {
			return
		}
		if subtle.ConstantTimeCompare([]byte(current), []byte(pwd)) == 1 {
			_ = writeClipboard("")
		}
	})

	return nil
}
