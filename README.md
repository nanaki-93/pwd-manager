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
| `pwd-manager touchid enable` | Unlock with Touch ID instead of typing the master password (macOS) |
| `pwd-manager touchid disable` | Stop using Touch ID and remove the saved master password |

## Touch ID (macOS)

`pwd-manager touchid enable` checks your fingerprint, verifies your master password and saves it in the macOS Keychain (service `pwd-manager`, account `master`, this device only). It also creates `~/.pwd-mng-touchid`. While that file exists, `get`, `list`, `add`, `remove` and the daemon show a Touch ID prompt first, then unlock the store with the saved password.

If Touch ID is unavailable, you cancel the prompt or the saved password no longer works, you're asked for the master password as usual. A saved password that no longer works is deleted, and Touch ID is turned off. `pwd-manager master` updates the saved copy when you change the master password. Touch ID needs a macOS build with cgo enabled. Other builds always ask for the master password.

## Build and test

Requires Go 1.23+ and [just](https://github.com/casey/just).

```sh
just setup   # download modules, install git hooks
just test    # run the test suite with the race detector
just check   # gofmt, go vet and tests
```

## License

MIT — see [LICENSE](LICENSE).
