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

## Build and test

Requires Go 1.23+ and [just](https://github.com/casey/just).

```sh
just setup   # download modules, install git hooks
just test    # run the test suite with the race detector
just check   # gofmt, go vet and tests
```

## License

MIT — see [LICENSE](LICENSE).
