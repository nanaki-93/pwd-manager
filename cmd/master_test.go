package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"github.com/nanaki-93/pwd-manager/internal/utils"
	"golang.org/x/crypto/pbkdf2"
)

func init() {
	setUtilsExit(func(int) {})
}

func withTempHome(t *testing.T) string {
	t.Helper()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	revExit := setUtilsExit(func(int) {})
	t.Cleanup(func() {
		utils.SetMasterKey(nil)
		revExit()
		_ = os.Chdir(origWd)
	})

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv(utils.LegacyMigrationEnv, "1") // fixtures seed legacy key-file stores
	utils.SetMasterKey(nil)
	return tmpHome
}

func writeTestKey(t *testing.T, tmpHome string, b byte) string {
	t.Helper()
	keyBytes := bytes.Repeat([]byte{b}, 32)
	utils.SetMasterKey(keyBytes)
	keyPath := filepath.Join(tmpHome, utils.PwdFileKey)
	if err := os.WriteFile(keyPath, keyBytes, 0700); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	return keyPath
}

func captureExit(t *testing.T) *int {
	t.Helper()
	var count int
	restore := setUtilsExit(func(code int) {
		if code != 0 {
			count++
		}
	})
	t.Cleanup(restore)
	return &count
}

func stubFixedRandSalt(t *testing.T, fill byte, err error) *[]byte {
	t.Helper()
	origRandRead := randRead
	t.Cleanup(func() { randRead = origRandRead })
	var captured []byte
	randRead = func(r io.Reader, buf []byte) (int, error) {
		captured = buf
		for i := range buf {
			buf[i] = fill
		}
		if err != nil {
			return 0, err
		}
		return len(buf), nil
	}
	return &captured
}

func feedStdinInput(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		_ = r.Close()
	}()
	if _, err := w.WriteString(input); err != nil {
		t.Fatalf("failed to write stdin input: %v", err)
	}
	_ = w.Close()
	fn()
}

func stubPasswordSequence(t *testing.T, inputs ...string) {
	t.Helper()
	idx := 0
	restore := setUtilsReadPassword(func() ([]byte, error) {
		if idx >= len(inputs) {
			return nil, errors.New("unexpected password prompt")
		}
		p := []byte(inputs[idx])
		idx++
		return p, nil
	})
	t.Cleanup(restore)
}

func assertWeakPasswordRejected(t *testing.T, tmpHome, candidate, wantErr string) {
	t.Helper()
	err := validateMasterPassword([]byte(candidate))
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("validateMasterPassword(%q) = %v, want error containing %q", candidate, err, wantErr)
	}

	stubPasswordSequence(t, candidate)
	exitCount := captureExit(t)
	savePassword(model.PwdFile{})

	if *exitCount == 0 {
		t.Fatalf("expected ManageErrorAndExit to be called for weak master password %q", candidate)
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected password file not to be written for weak password %q, stat err: %v", candidate, statErr)
	}
}

const minAcceptedKDFIterations = 600_000

func readStoredSaltParams(t *testing.T, tmpHome string) (int, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(tmpHome, keyDerivationSaltFile))
	if err != nil {
		t.Fatalf("read salt file: %v", err)
	}
	if len(data) != len(keySaltMagic)+4+keyDerivationSaltLen || !bytes.HasPrefix(data, []byte(keySaltMagic)) {
		t.Fatalf("salt file does not record KDF parameters: %x", data)
	}
	iter := int(binary.BigEndian.Uint32(data[len(keySaltMagic) : len(keySaltMagic)+4]))
	return iter, data[len(keySaltMagic)+4:]
}

func fillSyntheticSecret(dst []byte, seed byte) {
	for i := range dst {
		dst[i] = byte('!' + (int(seed)+i*13)%90)
	}
}

func verifyZeroedBuffersAndHeap(t *testing.T, tmpHome string, buffers [][]byte, wantCount int, seeds []byte) {
	t.Helper()
	dumpPath := filepath.Join(tmpHome, "heap.dump")
	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		t.Fatalf("failed to create heap dump file: %v", err)
	}
	debug.WriteHeapDump(dumpFile.Fd())
	if err := dumpFile.Close(); err != nil {
		t.Fatalf("failed to close heap dump file: %v", err)
	}
	if len(buffers) != wantCount {
		t.Fatalf("expected %d password prompts, got %d", wantCount, len(buffers))
	}
	for i, buf := range buffers {
		if !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatalf("expected password buffer %d to be zeroed in memory, got %x", i, buf)
		}
	}
	dumpBytes, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("failed to read heap dump: %v", err)
	}
	for _, seed := range seeds {
		probe := make([]byte, 24)
		fillSyntheticSecret(probe, seed)
		if bytes.Contains(dumpBytes, probe) {
			t.Fatalf("found raw secret for seed %d in runtime heap snapshot", seed)
		}
		clear(probe)
	}
}

func TestWriteKeySaltBoundaryAndErrorPaths(t *testing.T) {
	tmpHome := withTempHome(t)
	saltPath := filepath.Join(tmpHome, keyDerivationSaltFile)

	if err := os.Mkdir(saltPath, 0o700); err != nil {
		t.Fatalf("failed to create directory at salt path: %v", err)
	}
	var pathErr *os.PathError
	if err := writeKeySalt(bytes.Repeat([]byte{0x01}, keyDerivationSaltLen)); !errors.As(err, &pathErr) {
		t.Fatalf("expected *os.PathError from writeKeySalt when salt path is a directory, got: %v", err)
	}
	if err := writeKeySalt(nil); err == nil || !strings.Contains(err.Error(), "salt cannot be empty") {
		t.Fatalf("expected empty salt error from writeKeySalt(nil), got: %v", err)
	}
}

func TestWriteKeySaltRefusesSymlinkAndKeepsTarget(t *testing.T) {
	home := withTempHome(t)
	target := filepath.Join(t.TempDir(), "victim")
	orig := []byte("do not overwrite")
	if err := os.WriteFile(target, orig, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(home, keyDerivationSaltFile)); err != nil {
		t.Fatalf("symlink salt: %v", err)
	}
	if err := writeKeySalt(bytes.Repeat([]byte{2}, keyDerivationSaltLen)); err == nil {
		t.Fatal("expected writeKeySalt to refuse a symlinked salt path")
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
}

func TestWriteKeySaltWrapsTemporaryFileFailure(t *testing.T) {
	home := withTempHome(t)
	missingHome := filepath.Join(home, "missing")
	original := userHomeDir
	userHomeDir = func() (string, error) { return missingHome, nil }
	t.Cleanup(func() { userHomeDir = original })
	err := writeKeySalt(bytes.Repeat([]byte{2}, keyDerivationSaltLen))
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "write salt file: create temp file:") {
		t.Fatalf("missing wrapped salt persistence context: %v", err)
	}
	if entries, err := os.ReadDir(home); err != nil || len(entries) != 0 {
		t.Fatalf("expected no files in home after failed write, got %d entries (err=%v)", len(entries), err)
	}
}

// A failed open, or a symlink swapped in after the regular-file check, is
// refused without touching the caller's salt buffer.
func TestReadKeySaltRefusesFailedOrSwappedOpen(t *testing.T) {
	cause := errors.New("injected open failure")
	cases := []struct {
		name    string
		open    func(t *testing.T, prev func(string) (*os.File, error), name string) (*os.File, error)
		wantErr func(error) bool
	}{
		{"open failure", func(*testing.T, func(string) (*os.File, error), string) (*os.File, error) {
			return nil, cause
		}, func(err error) bool { return errors.Is(err, cause) && strings.Contains(err.Error(), "open salt file:") }},
		{"symlink swapped in", swapSaltForSymlink, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "not a regular file")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := withTempHome(t)
			if err := os.WriteFile(filepath.Join(home, keyDerivationSaltFile), bytes.Repeat([]byte{1}, keyDerivationSaltLen), 0o600); err != nil {
				t.Fatalf("write salt: %v", err)
			}
			prev := openKeyFile
			openKeyFile = func(name string) (*os.File, error) { return tc.open(t, prev, name) }
			t.Cleanup(func() { openKeyFile = prev })
			salt := bytes.Repeat([]byte{7}, keyDerivationSaltLen)
			iterations, loaded, err := readKeySalt(salt)
			if !tc.wantErr(err) {
				t.Fatalf("unexpected readKeySalt error: %v", err)
			}
			if loaded || iterations != 0 || !bytes.Equal(salt, bytes.Repeat([]byte{7}, keyDerivationSaltLen)) {
				t.Fatalf("failed read changed caller output: loaded=%v iterations=%d", loaded, iterations)
			}
		})
	}
}

// swapSaltForSymlink simulates the race: it replaces the checked salt file
// with a symlink to another file before opening it.
func swapSaltForSymlink(t *testing.T, prev func(string) (*os.File, error), name string) (*os.File, error) {
	target := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(target, bytes.Repeat([]byte{9}, keyDerivationSaltLen), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatalf("remove salt: %v", err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatalf("symlink salt: %v", err)
	}
	return prev(name)
}

func TestParseKeySaltRejectsOutOfRangeIterations(t *testing.T) {
	for _, iter := range []uint32{0, legacyKeyDerivationIterations - 1, maxKeyDerivationIterations + 1} {
		data := binary.BigEndian.AppendUint32([]byte(keySaltMagic), iter)
		data = append(data, make([]byte, keyDerivationSaltLen)...)
		if _, _, err := parseKeySalt(data, keyDerivationSaltLen); err == nil {
			t.Fatalf("parseKeySalt accepted %d iterations", iter)
		}
	}
}

// deriveKey runs PBKDF2-HMAC-SHA256 at the given count; the default count is
// the strong 600,000-iteration work factor, not the legacy one.
func TestDeriveKeyMatchesPBKDF2AtGivenIterations(t *testing.T) {
	useRealKDF(t)
	password := []byte("valid-master-secret")
	salt := bytes.Repeat([]byte{0x5c}, keyDerivationSaltLen)
	cases := []struct{ given, want int }{
		{keyDerivationIterations, minAcceptedKDFIterations},
		{legacyKeyDerivationIterations, legacyKeyDerivationIterations},
	}
	for _, tc := range cases {
		got, err := deriveKey(password, salt, tc.given)
		if err != nil || !bytes.Equal(got, pbkdf2.Key(password, salt, tc.want, encryptionKeyLen, sha256.New)) {
			t.Fatalf("deriveKey(%d iterations) does not match PBKDF2 at %d (err=%v)", tc.given, tc.want, err)
		}
	}
}

func TestDeriveKeyValidationBoundaries(t *testing.T) {
	saltA := bytes.Repeat([]byte{0x11}, 32)
	saltB := bytes.Repeat([]byte{0x22}, 32)

	for _, invalidPwd := range [][]byte{nil, []byte(""), []byte("   "), []byte("short77")} {
		if _, err := deriveKey(invalidPwd, saltA, keyDerivationIterations); err == nil {
			t.Fatalf("expected deriveKey to reject weak password %q", invalidPwd)
		}
	}
	if _, err := deriveKey([]byte("valid-master-secret"), nil, keyDerivationIterations); err == nil || !strings.Contains(err.Error(), "salt cannot be empty") {
		t.Fatalf("expected empty salt error from deriveKey, got %v", err)
	}
	for _, iter := range []int{0, legacyKeyDerivationIterations - 1, maxKeyDerivationIterations + 1} {
		if _, err := deriveKey([]byte("valid-master-secret"), saltA, iter); err == nil {
			t.Fatalf("deriveKey accepted %d iterations", iter)
		}
	}

	k1, err := deriveKey([]byte("password-alpha"), saltA, keyDerivationIterations)
	if err != nil || len(k1) != encryptionKeyLen {
		t.Fatalf("expected %d-byte derived key, got len=%d err=%v", encryptionKeyLen, len(k1), err)
	}
	k1Repeat, _ := deriveKey([]byte("password-alpha"), saltA, keyDerivationIterations)
	kDiffSalt, _ := deriveKey([]byte("password-alpha"), saltB, keyDerivationIterations)
	kDiffPwd, _ := deriveKey([]byte("password-bravo"), saltA, keyDerivationIterations)
	if !bytes.Equal(k1, k1Repeat) || bytes.Equal(k1, kDiffSalt) || bytes.Equal(k1, kDiffPwd) {
		t.Fatalf("expected deterministic key derivation sensitive to both password and salt")
	}
}

// Rotation rewrites a legacy raw salt or a weaker recorded header at the
// current count before the store is saved under the matching key.
func TestRotateMasterKeyUpgradesSaltHeaderBeforeSave(t *testing.T) {
	salt := bytes.Repeat([]byte{0x73}, keyDerivationSaltLen)
	cases := map[string][]byte{
		"legacy raw salt":  salt,
		"weaker iteration": append(binary.BigEndian.AppendUint32([]byte(keySaltMagic), 200_000), salt...),
	}
	for name, seeded := range cases {
		t.Run(name, func(t *testing.T) {
			home := withTempHome(t)
			if err := os.WriteFile(filepath.Join(home, keyDerivationSaltFile), seeded, 0o600); err != nil {
				t.Fatalf("seed salt: %v", err)
			}
			originalSave := saveStore
			t.Cleanup(func() { saveStore = originalSave })
			calls := 0
			saveStore = func(content model.PwdFile, upstream error) error {
				calls++
				iterations, storedSalt := readStoredSaltParams(t, home)
				if iterations != keyDerivationIterations || !bytes.Equal(storedSalt, salt) {
					t.Fatalf("save began before upgraded header persisted: (%d, %x)", iterations, storedSalt)
				}
				return originalSave(content, upstream)
			}
			password := []byte("rotated-master-secret")
			content := model.PwdFile{MasterPassword: "fixture-hash", SavedPasswords: map[string]string{"mail": "secret"}}
			if err := rotateMasterKey(password, content); err != nil || calls != 1 {
				t.Fatalf("rotate: err=%v, save calls = %d, want 1", err, calls)
			}
			utils.SetMasterKey(pbkdf2Key(password, salt, keyDerivationIterations, encryptionKeyLen, sha256.New))
			loaded, err := utils.GetPwdObj()
			if err != nil || loaded.MasterPassword != content.MasterPassword || loaded.SavedPasswords["mail"] != "secret" {
				t.Fatalf("store not encrypted at upgraded count: content=%+v, err=%v", loaded, err)
			}
		})
	}
}

func TestExecMasterCmdDoesNotOverwriteKeyOnCorruptFile(t *testing.T) {
	tmpHome := withTempHome(t)
	existingKey := bytes.Repeat([]byte{0x42}, 32)
	keyPath := writeTestKey(t, tmpHome, 0x42)
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	corruptContent := bytes.Repeat([]byte{0x99}, 32)
	if err := os.WriteFile(pwdPath, corruptContent, 0700); err != nil {
		t.Fatalf("failed to write corrupt password file: %v", err)
	}

	execMasterCmd(masterCmd, nil)

	if gotKey, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(gotKey, existingKey) {
		t.Fatalf("existing key was overwritten on non-ErrNotExist load failure (err=%v)", err)
	}
	if gotPwdFile, err := os.ReadFile(pwdPath); err != nil || !bytes.Equal(gotPwdFile, corruptContent) {
		t.Fatalf("existing password file was overwritten on non-ErrNotExist load failure (err=%v)", err)
	}
}

func TestExecMasterCmdAbortsWhenKeyGenerationFails(t *testing.T) {
	tmpHome := withTempHome(t)
	stubPasswordSequence(t, "first-time-secret")
	_ = stubFixedRandSalt(t, 0, errors.New("entropy exhausted"))

	execMasterCmd(masterCmd, nil)

	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no key file when key generation fails, got stat err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no password file when key generation fails, got stat err: %v", err)
	}
}

func TestExecMasterCmdInitializesHashedPasswordWithoutKeyFile(t *testing.T) {
	tmpHome := withTempHome(t)
	stubPasswordSequence(t, "first-time-secret")
	execMasterCmd(masterCmd, nil)

	if _, err := os.Stat(filepath.Join(tmpHome, utils.PwdFileKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no key file on disk after master command, got stat err: %v", err)
	}
	loaded, err := utils.GetPwdObj()
	if err != nil || !strings.HasPrefix(loaded.MasterPassword, "pbkdf2-sha256$") {
		t.Fatalf("expected salted PBKDF2 hash prefix, got %q (err=%v)", loaded.MasterPassword, err)
	}
	if !utils.VerifyMasterPassword(loaded.MasterPassword, []byte("first-time-secret")) {
		t.Fatalf("expected saved master password hash to verify against initial secret")
	}
}

// Declines (including empty input and EOF) keep the hash without aborting; a
// non-canonical affirmative answer reaches savePassword and rotates it.
func TestExecMasterCmdUpdateConfirmation(t *testing.T) {
	_ = withTempHome(t)
	stubPasswordSequence(t, "initial-secret", "initial-secret", "updated-secret")
	execMasterCmd(masterCmd, nil)
	initial, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("initial setup: %v", err)
	}

	exitCount := captureExit(t)
	declines := []string{"n\n", "N\n", "no\n", "NO\n", "yeah\n", "yess\n", "\n", "  \n", "\r\n", ""}
	for _, input := range declines {
		feedStdinInput(t, input, func() { execMasterCmd(masterCmd, nil) })
		if *exitCount != 0 {
			t.Fatalf("confirmation %q aborted with %d exits, want a decline", input, *exitCount)
		}
		loaded, err := utils.GetPwdObj()
		if err != nil || loaded.MasterPassword != initial.MasterPassword {
			t.Fatalf("confirmation %q changed the master password (err=%v)", input, err)
		}
	}

	feedStdinInput(t, "  yEs  \n", func() { execMasterCmd(masterCmd, nil) })
	loaded, err := utils.GetPwdObj()
	if err != nil || !utils.VerifyMasterPassword(loaded.MasterPassword, []byte("updated-secret")) {
		t.Fatalf("expected %q confirmation to update password, err=%v", "  yEs  \n", err)
	}
}

func TestIsAffirmative(t *testing.T) {
	cases := map[string]bool{
		"Y": true, "y": true, "yes": true, "YES": true, "  YeS": true,
		"\tY\t": true, "  yEs  ": true, "y\r": true,
		"": false, "  ": false, "n": false, "N": false, "no": false, "NO": false,
		"yeah": false, "yess": false, "y es": false,
	}
	for answer, want := range cases {
		if got := isAffirmative(answer); got != want {
			t.Fatalf("isAffirmative(%q) = %v, want %v", answer, got, want)
		}
	}
}

type errConfirmReader struct{ err error }

func (f errConfirmReader) Read([]byte) (int, error) { return 0, f.err }

func TestReadConfirmation(t *testing.T) {
	cases := map[string]string{"y\n": "y", "\n": "", "": "", "yes": "yes", "n\nrest\n": "n"}
	for input, want := range cases {
		got, err := readConfirmation(strings.NewReader(input))
		if err != nil || got != want {
			t.Fatalf("readConfirmation(%q) = (%q, %v), want (%q, nil)", input, got, err, want)
		}
	}
	readErr := errors.New("device gone")
	if _, err := readConfirmation(errConfirmReader{readErr}); !errors.Is(err, readErr) {
		t.Fatalf("readConfirmation read error = %v, want wrapped %v", err, readErr)
	}
}

// A store that holds entries but has an empty master hash must not be treated
// as initialization: the master command refuses to rotate its key.
func TestExecMasterCmdRefusesExistingStoreWithEmptyHash(t *testing.T) {
	tmpHome := withTempHome(t)
	utils.SetMasterKey([]byte("original-secret"))
	fixture := model.PwdFile{SavedPasswords: map[string]string{"bank": "hunter22"}}
	if err := utils.SaveFileErr(fixture, nil); err != nil {
		t.Fatalf("write fixture store: %v", err)
	}
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	before, err := os.ReadFile(pwdPath)
	if err != nil {
		t.Fatalf("read fixture store: %v", err)
	}
	stubPasswordSequence(t, "attacker-chosen-secret")
	exitCount := captureExit(t)

	output := captureStdout(t, func() {
		feedStdinInput(t, "y\n", func() { execMasterCmd(masterCmd, nil) })
	})

	if *exitCount == 0 || !strings.Contains(output, errMissingMasterHash.Error()) {
		t.Fatalf("expected missing-hash error and exit, got %d exits, output %q", *exitCount, output)
	}
	if strings.Contains(output, "Enter your new password:") {
		t.Fatalf("did not expect a new password prompt, got %q", output)
	}
	after, err := os.ReadFile(pwdPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("store was rewritten despite missing master hash (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(tmpHome, keyDerivationSaltFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no salt file written, got stat err: %v", err)
	}
}

func TestRequireMasterHash(t *testing.T) {
	withEntries := model.PwdFile{SavedPasswords: map[string]string{"a": "b"}}
	cases := []struct {
		name    string
		content model.PwdFile
		exists  bool
		wantErr bool
	}{
		{"fresh init", model.PwdFile{}, false, false},
		{"existing store empty hash", model.PwdFile{}, true, true},
		{"entries without hash", withEntries, false, true},
		{"hash present", model.PwdFile{MasterPassword: "pbkdf2-sha256$x"}, true, false},
	}
	for _, tc := range cases {
		err := requireMasterHash(tc.content, tc.exists)
		if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, errMissingMasterHash)) {
			t.Fatalf("%s: requireMasterHash = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestSavePasswordRefusesEntriesWithoutHash(t *testing.T) {
	_ = withTempHome(t)
	stubPasswordSequence(t, "attacker-chosen-secret")
	exitCount := captureExit(t)
	output := captureStdout(t, func() {
		savePassword(model.PwdFile{SavedPasswords: map[string]string{"bank": "hunter22"}})
	})
	if *exitCount == 0 || strings.Contains(output, "Password saved") {
		t.Fatalf("expected refusal for entries without a master hash, got %d exits, output %q", *exitCount, output)
	}
}

func TestSavePasswordRejectsEmptyAndWeakInputs(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)

	tests := []struct{ name, candidate, wantErr string }{
		{"empty input", "", "master password cannot be empty"},
		{"whitespace only input", "   \t\n  ", "master password cannot be empty"},
		{"short input", "short", "at least 8 characters"},
		{"seven character boundary input", "1234567", "at least 8 characters"},
		{"padded short input", "  1234567  ", "at least 8 characters"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertWeakPasswordRejected(t, tmpHome, tc.candidate, tc.wantErr)
		})
	}
	if err := validateMasterPassword([]byte("12345678")); err != nil {
		t.Fatalf("expected 8-character password to pass validation, got: %v", err)
	}
}

func TestSavePasswordRejectsNilReaderSlice(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)

	if err := validateMasterPassword(nil); err == nil || !strings.Contains(err.Error(), "master password cannot be empty") {
		t.Fatalf("validateMasterPassword(nil) = %v, want empty master password error", err)
	}

	origRandRead := randRead
	defer func() { randRead = origRandRead }()
	keyGenCalled := false
	randRead = func(r io.Reader, buf []byte) (int, error) {
		keyGenCalled = true
		return len(buf), nil
	}

	restoreReader := setUtilsReadPassword(func() ([]byte, error) { return nil, nil })
	defer restoreReader()

	exitCount := captureExit(t)
	savePassword(model.PwdFile{})

	if *exitCount != 1 {
		t.Fatalf("expected ManageErrorAndExit to be called once on validation failure when reader returns (nil, nil), got %d", *exitCount)
	}
	if keyGenCalled {
		t.Fatalf("expected key generation not to run when new password slice is nil")
	}
	if _, statErr := os.Stat(filepath.Join(tmpHome, utils.PwdFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected password file not to be written when reader returns (nil, nil), stat err: %v", statErr)
	}
}

func TestSavePasswordInitialAndMismatch(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)
	stubPasswordSequence(t, "initial-master-password", "wrong-current-password")

	savePassword(model.PwdFile{})
	persisted, err := utils.GetPwdObj()
	if err != nil || !strings.HasPrefix(persisted.MasterPassword, "pbkdf2-sha256$") {
		t.Fatalf("expected persisted pbkdf2-sha256$ hash, got %q (err=%v)", persisted.MasterPassword, err)
	}
	if !utils.VerifyMasterPassword(persisted.MasterPassword, []byte("initial-master-password")) {
		t.Fatalf("expected persisted master password hash to verify against initial password")
	}

	savePassword(persisted)
	afterMismatch, err := utils.GetPwdObj()
	if err != nil || afterMismatch.MasterPassword != persisted.MasterPassword {
		t.Fatalf("expected master password hash to remain unchanged on mismatch (err=%v)", err)
	}
}

func TestSavePasswordRotationAndPromptError(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)
	stubPasswordSequence(t, "initial-master-password", "initial-master-password", "rotated-master-password")

	savePassword(model.PwdFile{})
	persisted, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to load initial password file: %v", err)
	}

	savePassword(persisted)
	afterRotate, err := utils.GetPwdObj()
	if err != nil || afterRotate.MasterPassword == persisted.MasterPassword {
		t.Fatalf("expected rotated master password hash to differ from previous hash (err=%v)", err)
	}
	if !utils.VerifyMasterPassword(afterRotate.MasterPassword, []byte("rotated-master-password")) ||
		utils.VerifyMasterPassword(afterRotate.MasterPassword, []byte("initial-master-password")) {
		t.Fatalf("expected rotated hash to verify new password and reject old password")
	}

	exitCount := captureExit(t)
	savePassword(afterRotate)
	if *exitCount == 0 {
		t.Fatalf("expected ManageErrorAndExit to be called when password prompt fails")
	}
	if afterPromptErr, err := utils.GetPwdObj(); err != nil || afterPromptErr.MasterPassword != afterRotate.MasterPassword {
		t.Fatalf("expected master password hash to remain unchanged after prompt failure (err=%v)", err)
	}
}

func TestSavePasswordZeroesPasswordBuffersAndHeapSnapshot(t *testing.T) {
	tmpHome := withTempHome(t)
	writeTestKey(t, tmpHome, 0x77)

	var buffers [][]byte
	seeds := []byte{11, 29, 11, 47, 11, 83}
	lens := []int{24, 24, 24, 5, 24, 24}
	idx := 0
	restoreReader := setUtilsReadPassword(func() ([]byte, error) {
		if idx >= len(seeds) {
			return nil, errors.New("unexpected password prompt")
		}
		buf := make([]byte, lens[idx])
		fillSyntheticSecret(buf, seeds[idx])
		idx++
		buffers = append(buffers, buf)
		return buf, nil
	})
	defer restoreReader()

	savePassword(model.PwdFile{})
	persisted, err := utils.GetPwdObj()
	if err != nil {
		t.Fatalf("failed to load initial password file: %v", err)
	}
	savePassword(persisted)
	savePassword(persisted)
	savePassword(persisted)
	utils.SetMasterKey(nil)

	verifyZeroedBuffersAndHeap(t, tmpHome, buffers, len(seeds), []byte{11, 29, 83})
}

func TestSavePasswordAbortsWhenEncryptionFails(t *testing.T) {
	tmpHome := withTempHome(t)
	stubPasswordSequence(t, "new-master-password")
	pwdPath := filepath.Join(tmpHome, utils.PwdFileName)
	if err := os.Mkdir(pwdPath, 0700); err != nil {
		t.Fatalf("failed to create directory at password file path: %v", err)
	}

	exitCount := captureExit(t)
	savePassword(model.PwdFile{})
	if *exitCount == 0 {
		t.Fatalf("expected ManageErrorAndExit to be invoked when saving encrypted file fails in savePassword")
	}
	if info, err := os.Stat(pwdPath); err != nil || !info.IsDir() {
		t.Fatalf("expected directory at password file path to remain untouched on save failure, got: %v", err)
	}
}
