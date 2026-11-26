# pwd-manager

A local command-line password manager written in Go. Passwords are encrypted on disk with AES-GCM, using a key derived from your master password with PBKDF2. A background daemon lets you copy a password with a hotkey, and the clipboard is cleared automatically afterwards.

## Commands

| Command | What it does |
| --- | --- |
| `pwd-manager master` | Create or update your master password |
| `pwd-manager add` | Save a new password |
| `pwd-manager get <name>` | Copy a password by name |
| `pwd-manager list` | List saved passwords (`--json` supported) |
| `pwd-manager remove <name>` | Delete a saved password |
| `pwd-manager daemon` | Start the background service for hotkey access |
| `pwd-manager autostart enable` | Start the daemon automatically at login (macOS) |
| `pwd-manager autostart disable` | Stop starting the daemon at login |
| `pwd-manager touchid enable` | Unlock with Touch ID instead of typing the master password (macOS) |
| `pwd-manager touchid disable` | Stop using Touch ID and remove the saved master password |

## Password window

While `pwd-manager daemon` runs, Ctrl+Shift+P opens the password window. Unlock it with Touch ID (when enabled) or your master password. Then you can copy, edit, add or delete passwords. Copied passwords are cleared from the clipboard automatically. Type in the search field to filter the list. Closing the window, pressing Lock or leaving it idle for two minutes locks the store again.

The window stays on top of other apps' windows, including full-screen apps, until you close or lock it.

## Start at login (macOS)

`pwd-manager autostart enable` writes the LaunchAgent `~/Library/LaunchAgents/com.github.nanaki.pwd-manager.plist` and loads it, which starts the daemon right away and again at every login. The agent runs `daemon --restart` from the binary's current path and restarts it if it crashes. Its output goes to `daemon.log` in the user cache dir. If you move the binary, run `autostart enable` again. `just install` replaces the binary in place, so the agent keeps working. `pwd-manager autostart disable` unloads and removes the agent, which also stops a daemon the agent started.

## Touch ID (macOS)

`pwd-manager touchid enable` checks your fingerprint, verifies your master password and saves it in the macOS Keychain (service `pwd-manager`, account `master`, this device only). It also creates `~/.pwd-mng-touchid`. While that file exists, `get`, `list`, `add`, `remove` and the daemon show a Touch ID prompt first, then unlock the store with the saved password.

If Touch ID is unavailable, you cancel the prompt or the saved password no longer works, you're asked for the master password as usual. A saved password that no longer works is deleted, and Touch ID is turned off. `pwd-manager master` updates the saved copy when you change the master password. Touch ID needs a macOS build with cgo enabled. Other builds always ask for the master password.

## Build and test

Requires Go 1.23+ and [just](https://github.com/casey/just). The password window uses [Fyne](https://fyne.io), so building needs cgo and the OpenGL development headers (on Linux, for example `libgl1-mesa-dev` and `xorg-dev`).

```sh
just setup   # download modules, install git hooks
just test    # run the test suite with the race detector
just check   # gofmt, go vet and tests
```

## License

MIT — see [LICENSE](LICENSE).
