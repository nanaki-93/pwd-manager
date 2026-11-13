/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"golang.org/x/crypto/ssh/terminal"
)

const PwdFileName = ".pwd-mng"
const PwdFileKey = ".pwd-key"

// FormatMarkerName is written beside the store once a v3 store has been saved.
const FormatMarkerName = ".pwd-mng-v3"

// LegacyMigrationEnv must be "1" to read a headerless store with the legacy key
// file, so it can be migrated to the password-derived format once.
const LegacyMigrationEnv = "PWD_MNG_MIGRATE_LEGACY"

const (
	hashPrefix     = "pbkdf2-sha256$"
	saltSize       = 16
	derivedKeySize = 32
	sensitivePerm  = 0600
	// pbkdf2Iter is the current PBKDF2-HMAC-SHA256 work factor. It is recorded in
	// both the hash string and the v3 store header so it can be raised later.
	pbkdf2Iter = 600000
	// legacyPBKDF2Iter is the fixed work factor of hashes and v2 stores written
	// before parameters were recorded; they are upgraded on the next unlock.
	legacyPBKDF2Iter = 100000
	// maxPBKDF2Iter bounds parsed iteration counts so a crafted file cannot stall unlocks.
	maxPBKDF2Iter = 10000000
	v2Magic       = "PWD2"
	v3Magic       = "PWD3"
	iterFieldSize = 4
)

var (
	randRead = io.ReadFull
	// ExitFunc terminates the process after ManageErrorAndExit reports an error.
	ExitFunc = os.Exit
	// ReadPasswordStdin reads a password from the terminal without echo.
	ReadPasswordStdin = func() ([]byte, error) { return terminal.ReadPassword(int(syscall.Stdin)) }

	errDecryptFailed = errors.New("decrypt file err")
	ErrSymlink       = errors.New("refusing to access symlink")
	ErrNonRegular    = errors.New("refusing to access non-regular file")
	// ErrLegacyStore is returned for a headerless key-file store outside migration.
	ErrLegacyStore = errors.New("refusing legacy key-file store")
	// ErrMasterKeyRequired is returned when saving the store without a master password in memory.
	ErrMasterKeyRequired = errors.New("master password required to encrypt store")

	masterKeyMu      sync.RWMutex
	sessionMasterKey []byte
	// sessionDerived caches the salt and store key derived from sessionMasterKey at
	// pbkdf2Iter so saves in one session skip PBKDF2. Guarded by masterKeyMu and
	// wiped whenever the master key changes.
	sessionDerived *derivedKey
)

type derivedKey struct {
	salt []byte
	key  []byte
}

// SetMasterKey sets the active master password in memory for deriving the store encryption key.
// Any cached derived store key is wiped, so a new password always re-derives.
func SetMasterKey(password []byte) {
	masterKeyMu.Lock()
	defer masterKeyMu.Unlock()
	for i := range sessionMasterKey {
		sessionMasterKey[i] = 0
	}
	if sessionDerived != nil {
		wipeBytes(sessionDerived.key)
		sessionDerived = nil
	}
	if len(password) == 0 {
		sessionMasterKey = nil
		return
	}
	sessionMasterKey = append([]byte(nil), password...)
}

func getMasterKey() []byte {
	masterKeyMu.RLock()
	defer masterKeyMu.RUnlock()
	if len(sessionMasterKey) == 0 {
		return nil
	}
	return append([]byte(nil), sessionMasterKey...)
}

// cacheDerivedKey remembers key (derived from secret and salt at pbkdf2Iter) for
// reuse by later saves, but only while secret is still the session master key.
func cacheDerivedKey(secret, salt, key []byte, iter int) {
	if iter != pbkdf2Iter {
		return
	}
	masterKeyMu.Lock()
	defer masterKeyMu.Unlock()
	if len(sessionMasterKey) == 0 || subtle.ConstantTimeCompare(secret, sessionMasterKey) != 1 {
		return
	}
	if sessionDerived != nil {
		wipeBytes(sessionDerived.key)
	}
	sessionDerived = &derivedKey{
		salt: append([]byte(nil), salt...),
		key:  append([]byte(nil), key...),
	}
}

// getCachedDerivedKey returns copies of the cached salt and key derived from
// secret, or nils when there is none for it.
func getCachedDerivedKey(secret []byte) ([]byte, []byte) {
	masterKeyMu.RLock()
	defer masterKeyMu.RUnlock()
	if sessionDerived == nil || subtle.ConstantTimeCompare(secret, sessionMasterKey) != 1 {
		return nil, nil
	}
	return append([]byte(nil), sessionDerived.salt...), append([]byte(nil), sessionDerived.key...)
}

// wipeBytes overwrites b with zeros so secret copies do not linger on the heap.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func deriveEncryptionKey(secret, salt []byte, iter int) []byte {
	domainSalt := make([]byte, 0, len(salt)+len("enc-v2")+1)
	domainSalt = append(domainSalt, salt...)
	domainSalt = append(domainSalt, ':')
	domainSalt = append(domainSalt, "enc-v2"...)
	return kdf(secret, domainSalt, iter, derivedKeySize)
}

// kdf computes every PBKDF2-HMAC-SHA256 derivation of this package; a variable
// so this package's tests can swap in a cheaper function (see export_test.go)
// while recorded parameters stay unchanged. No exported API may replace it.
var kdf = pbkdf2SHA256

func validIterations(iter int) bool {
	return iter >= legacyPBKDF2Iter && iter <= maxPBKDF2Iter
}

// HashMasterPassword generates a salted PBKDF2-SHA256 hash of the supplied password
// in the form "pbkdf2-sha256$<iterations>$<salt hex>$<key hex>".
func HashMasterPassword(password []byte) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := randRead(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	dk := kdf(password, salt, pbkdf2Iter, derivedKeySize)
	return fmt.Sprintf("%s%d$%s$%s", hashPrefix, pbkdf2Iter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// VerifyMasterPassword checks candidate against stored in constant time.
// Legacy hashes without a recorded iteration count are verified with legacyPBKDF2Iter.
func VerifyMasterPassword(stored string, candidate []byte) bool {
	iter, salt, expectedDK, ok := parsePBKDF2Hash(stored)
	if !ok {
		return false
	}
	actualDK := kdf(candidate, salt, iter, derivedKeySize)
	return subtle.ConstantTimeCompare(expectedDK, actualDK) == 1
}

// hashNeedsUpgrade reports whether stored was written with a weaker work factor
// than pbkdf2Iter; higher iteration counts are kept as they are.
func hashNeedsUpgrade(stored string) bool {
	iter, _, _, ok := parsePBKDF2Hash(stored)
	return ok && iter < pbkdf2Iter
}

func parsePBKDF2Hash(stored string) (int, []byte, []byte, bool) {
	if !strings.HasPrefix(stored, hashPrefix) {
		return 0, nil, nil, false
	}
	parts := strings.Split(strings.TrimPrefix(stored, hashPrefix), "$")
	iter := legacyPBKDF2Iter
	switch len(parts) {
	case 2:
	case 3:
		n, err := strconv.Atoi(parts[0])
		if err != nil || !validIterations(n) {
			return 0, nil, nil, false
		}
		iter, parts = n, parts[1:]
	default:
		return 0, nil, nil, false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil || len(salt) != saltSize {
		return 0, nil, nil, false
	}
	dk, err := hex.DecodeString(parts[1])
	if err != nil || len(dk) != derivedKeySize {
		return 0, nil, nil, false
	}
	return iter, salt, dk, true
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}
	mac := hmac.New(sha256.New, password)
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	var intBuf [4]byte
	saltBlock := make([]byte, len(salt)+4)
	copy(saltBlock, salt)
	u := make([]byte, hashLen)
	uBuf := make([]byte, hashLen)
	t := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(intBuf[:], uint32(block))
		copy(saltBlock[len(salt):], intBuf[:])

		mac.Reset()
		mac.Write(saltBlock)
		u = mac.Sum(u[:0])
		copy(t, u)

		for i := 2; i <= iter; i++ {
			mac.Reset()
			mac.Write(u)
			uBuf = mac.Sum(uBuf[:0])
			for j := range t {
				t[j] ^= uBuf[j]
			}
			u, uBuf = uBuf, u
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func resolveHomePath(name string) (string, error) {
	if name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid file name %q", name)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	absHome, err := filepath.Abs(home)
	if err != nil {
		return "", fmt.Errorf("resolve absolute home dir: %w", err)
	}
	return filepath.Join(absHome, name), nil
}

func lstatRegularFile(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNonRegular, path)
	}
	return fi, nil
}

func ensureRegularOrMissing(path string) error {
	_, err := lstatRegularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func readSensitiveFile(path string) ([]byte, error) {
	fi, err := lstatRegularFile(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || !os.SameFile(fi, st) {
		return nil, fmt.Errorf("%w: %s", ErrNonRegular, path)
	}
	// Size the buffer from Stat so the read does not repeatedly grow and copy;
	// the extra MinRead lets ReadFrom see EOF without reallocating.
	buf := bytes.NewBuffer(make([]byte, 0, st.Size()+bytes.MinRead))
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return buf.Bytes(), nil
}

func writeTempSensitiveFile(tmpFile *os.File, content []byte) error {
	if err := tmpFile.Chmod(sensitivePerm); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return nil
}

func writeSensitiveFileAtomic(path string, content []byte) error {
	if err := ensureRegularOrMissing(path); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := writeTempSensitiveFile(tmpFile, content); err != nil {
		return err
	}
	if err := ensureRegularOrMissing(path); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	cleanup = false
	return nil
}

func removeSensitiveFileIfPresent(path string) error {
	if err := ensureRegularOrMissing(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove file: %w", err)
	}
	return nil
}

// encryptFile always writes the password-derived format. It never falls back to
// the legacy on-disk key file, which would downgrade the store and leave the key
// next to the vault.
func encryptFile(content []byte) error {
	secret := getMasterKey()
	defer wipeBytes(secret)
	if len(secret) == 0 {
		return fmt.Errorf("save store: %w", ErrMasterKeyRequired)
	}
	return encryptFileWithSecret(content, secret)
}

// encryptFileWithSecret reuses the session's cached salt and derived key when
// available; the random GCM nonce still makes every write's ciphertext unique.
func encryptFileWithSecret(content, secret []byte) error {
	salt, key := getCachedDerivedKey(secret)
	if key == nil {
		salt = make([]byte, saltSize)
		if _, err := randRead(rand.Reader, salt); err != nil {
			return fmt.Errorf("generate salt: %w", err)
		}
		key = deriveEncryptionKey(secret, salt, pbkdf2Iter)
		cacheDerivedKey(secret, salt, key, pbkdf2Iter)
	}
	defer wipeBytes(key)
	// v3 header: magic | uint32 big-endian PBKDF2 iterations | salt.
	prefix := make([]byte, 0, len(v3Magic)+iterFieldSize+saltSize)
	prefix = append(prefix, v3Magic...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(pbkdf2Iter))
	prefix = append(prefix, salt...)
	if err := encryptFileWithRawKey(content, key, prefix); err != nil {
		return err
	}
	if err := writeFormatMarker(); err != nil {
		return err
	}
	keyPath, err := resolveHomePath(PwdFileKey)
	if err != nil {
		return err
	}
	return removeSensitiveFileIfPresent(keyPath)
}

func encryptFileWithRawKey(content, key, prefix []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher GCM init: %w", err)
	}
	// One buffer holds prefix | nonce | ciphertext | tag, so Seal appends in place
	// instead of reallocating and the prefix needs no second copy.
	nonceSize := gcm.NonceSize()
	out := make([]byte, 0, len(prefix)+nonceSize+len(content)+gcm.Overhead())
	out = append(out, prefix...)
	out = out[:len(prefix)+nonceSize]
	nonce := out[len(prefix):]
	if _, err := randRead(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	cipherText := gcm.Seal(out, nonce, content, nil)
	pwdPath, err := resolveHomePath(PwdFileName)
	if err != nil {
		return err
	}
	if err := writeSensitiveFileAtomic(pwdPath, cipherText); err != nil {
		return fmt.Errorf("write encrypted file: %w", err)
	}
	return nil
}

// readPwdFileWithIter decrypts the store and returns the PBKDF2 iteration count it
// was encrypted with (0 for stores encrypted with the legacy raw key file).
func readPwdFileWithIter() ([]byte, int, error) {
	pwdPath, err := resolveHomePath(PwdFileName)
	if err != nil {
		return nil, 0, err
	}
	cipherText, err := readSensitiveFile(pwdPath)
	if err != nil {
		return nil, 0, err
	}
	if bytes.HasPrefix(cipherText, []byte(v3Magic)) {
		return decryptV3(cipherText[len(v3Magic):])
	}
	if bytes.HasPrefix(cipherText, []byte(v2Magic)) {
		plain, err := decryptV2(cipherText[len(v2Magic):])
		return plain, legacyPBKDF2Iter, err
	}
	return readLegacyKeyFileStore(cipherText)
}

// readLegacyKeyFileStore decrypts a headerless store with the raw key file. The
// key file needs no password, so this is allowed only while migrating: the user
// must opt in with LegacyMigrationEnv=1 and no v3 store may have been written.
func readLegacyKeyFileStore(cipherText []byte) ([]byte, int, error) {
	if err := legacyMigrationAllowed(); err != nil {
		return nil, 0, err
	}
	keyPath, err := resolveHomePath(PwdFileKey)
	if err != nil {
		return nil, 0, err
	}
	key, err := readSensitiveFile(keyPath)
	if err != nil {
		return nil, 0, err
	}
	defer wipeBytes(key)
	plain, err := decryptWithKey(cipherText, key)
	return plain, 0, err
}

func legacyMigrationAllowed() error {
	if os.Getenv(LegacyMigrationEnv) != "1" {
		return fmt.Errorf("%w: set %s=1 to migrate it once", ErrLegacyStore, LegacyMigrationEnv)
	}
	markerPath, err := resolveHomePath(FormatMarkerName)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(markerPath); err == nil {
		return fmt.Errorf("%w: a v3 store was already written", ErrLegacyStore)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check store format marker: %w", err)
	}
	return nil
}

// writeFormatMarker records that a v3 store was written, after which headerless
// stores are refused even with LegacyMigrationEnv set.
func writeFormatMarker() error {
	markerPath, err := resolveHomePath(FormatMarkerName)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(markerPath); err == nil {
		return nil
	}
	if err := writeSensitiveFileAtomic(markerPath, []byte(v3Magic)); err != nil {
		return fmt.Errorf("write store format marker: %w", err)
	}
	return nil
}

func decryptV3(payload []byte) ([]byte, int, error) {
	if len(payload) < iterFieldSize {
		return nil, 0, errors.New("ciphertext too short")
	}
	iter64 := uint64(binary.BigEndian.Uint32(payload[:iterFieldSize]))
	if iter64 > maxPBKDF2Iter || !validIterations(int(iter64)) {
		return nil, 0, fmt.Errorf("unsupported PBKDF2 iteration count %d in store header", iter64)
	}
	iter := int(iter64)
	plain, err := decryptWithDerivedKey(payload[iterFieldSize:], iter)
	return plain, iter, err
}

func decryptV2(payload []byte) ([]byte, error) {
	return decryptWithDerivedKey(payload, legacyPBKDF2Iter)
}

func decryptWithDerivedKey(payload []byte, iter int) ([]byte, error) {
	if len(payload) < saltSize {
		return nil, errors.New("ciphertext too short")
	}
	secret := getMasterKey()
	defer wipeBytes(secret)
	if len(secret) == 0 {
		return nil, errors.New("master password required to decrypt store")
	}
	salt := payload[:saltSize]
	key := deriveEncryptionKey(secret, salt, iter)
	defer wipeBytes(key)
	plain, err := decryptWithKey(payload[saltSize:], key)
	if err != nil {
		return nil, err
	}
	// Only a key that just authenticated the store is cached for later saves.
	cacheDerivedKey(secret, salt, key, iter)
	return plain, nil
}

func decryptWithKey(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher err: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher GCM err: %w", err)
	}
	if len(cipherText) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errDecryptFailed, err)
	}
	return plainText, nil
}

func GetPwdObj() (model.PwdFile, error) {
	content, _, err := getPwdObjWithIter()
	return content, err
}

func getPwdObjWithIter() (model.PwdFile, int, error) {
	content := model.PwdFile{}

	fileContent, iter, err := readPwdFileWithIter()
	if err != nil {
		return content, 0, err
	}

	err = json.Unmarshal(fileContent, &content)
	if err != nil {
		fmt.Println(err)
		return content, 0, err
	}

	return content, iter, nil
}

// upgradeKDFIfNeeded re-hashes the master password and re-encrypts the store with
// the current KDF parameters after a successful unlock with weaker ones. Stores
// and hashes already at or above pbkdf2Iter are left untouched.
func upgradeKDFIfNeeded(pwdObj *model.PwdFile, password []byte, storeIter int) error {
	rehash := hashNeedsUpgrade(pwdObj.MasterPassword)
	if !rehash && storeIter >= pbkdf2Iter {
		return nil
	}
	upgraded := *pwdObj
	if rehash {
		hashed, err := HashMasterPassword(password)
		if err != nil {
			return fmt.Errorf("rehash master password: %w", err)
		}
		upgraded.MasterPassword = hashed
	}
	if err := SaveFileErr(upgraded, nil); err != nil {
		return fmt.Errorf("re-encrypt store with current KDF parameters: %w", err)
	}
	*pwdObj = upgraded
	return nil
}

func PromptPasswordErr(textForPrompt string) ([]byte, error) {
	fmt.Println(textForPrompt)
	pwd, err := ReadPasswordStdin()
	if err != nil {
		return nil, err
	}
	if pwd == nil {
		return []byte{}, nil
	}
	return pwd, nil
}

func PromptPassword(textForPrompt string) []byte {
	promptedPassword, err := PromptPasswordErr(textForPrompt)
	ManageErrorAndExit(err)
	return promptedPassword
}

func SaveFileErr(currPwdContent model.PwdFile, err error) error {
	if err != nil {
		return err
	}
	jsonContent, marshalErr := toJsonContent(err, currPwdContent)
	if marshalErr != nil {
		return marshalErr
	}
	return encryptFile(jsonContent)
}

func toJsonContent(err error, pwdContent model.PwdFile) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	jsonContent, marshalErr := json.Marshal(pwdContent)
	if marshalErr != nil {
		return nil, marshalErr
	}
	return jsonContent, nil
}

func ManageErrorAndExit(err error) {
	if err != nil {
		fmt.Println(err)
		ExitFunc(1)
	}
}

// ErrWrongMasterPassword reports a master password that does not unlock the store.
var ErrWrongMasterPassword = errors.New("master passwords do not match")

// storeReadError marks a failure to read or decode the store, which the CLI
// treats as fatal; its message is the wrapped error's, unchanged.
type storeReadError struct{ err error }

func (e storeReadError) Error() string { return e.err.Error() }
func (e storeReadError) Unwrap() error { return e.err }

// requireStoreFile reports an error unless the store exists as a regular file.
func requireStoreFile() error {
	pwdPath, err := resolveHomePath(PwdFileName)
	if err != nil {
		return err
	}
	_, err = lstatRegularFile(pwdPath)
	return err
}

// GetPwdObjAfterCheckMaster prompts for the master password on stdin and
// unlocks the store, exiting the process on a missing store or a read failure.
func GetPwdObjAfterCheckMaster() (model.PwdFile, error) {
	if err := requireStoreFile(); err != nil {
		ManageErrorAndExit(err)
		return model.PwdFile{}, err
	}
	pwd := PromptPassword("Enter your master password:")
	// SetMasterKey keeps its own copy; the prompted buffer is wiped on return.
	defer wipeBytes(pwd)
	pwdObj, err := unlockWithPassword(pwd)
	var readErr storeReadError
	if errors.As(err, &readErr) {
		ManageErrorAndExit(readErr.err)
		return model.PwdFile{}, readErr.err
	}
	return pwdObj, err
}

// UnlockStore unlocks the store with the master password pwd and returns
// every failure, including a wrong password, as an error instead of exiting,
// so long-running callers such as the daemon survive it. The caller owns pwd.
func UnlockStore(pwd []byte) (model.PwdFile, error) {
	if err := requireStoreFile(); err != nil {
		return model.PwdFile{}, fmt.Errorf("open password store: %w", err)
	}
	pwdObj, err := unlockWithPassword(pwd)
	if err != nil {
		return model.PwdFile{}, fmt.Errorf("unlock password store: %w", err)
	}
	return pwdObj, nil
}

// unlockWithPassword sets the master key from pwd, decrypts and verifies the
// store and upgrades its KDF parameters when needed. Read failures are
// returned as storeReadError; on any failure the master key is cleared.
func unlockWithPassword(pwd []byte) (model.PwdFile, error) {
	SetMasterKey(pwd)
	pwdObj, storeIter, err := getPwdObjWithIter()
	if err != nil {
		SetMasterKey(nil)
		if errors.Is(err, errDecryptFailed) {
			return model.PwdFile{}, ErrWrongMasterPassword
		}
		return model.PwdFile{}, storeReadError{err: err}
	}
	// A positive storeIter means the store was AES-GCM authenticated with a key
	// derived from pwd, which already proves the password; skip a second PBKDF2.
	// Legacy key-file stores (storeIter 0) decrypt without it, so check the hash.
	if storeIter == 0 && !VerifyMasterPassword(pwdObj.MasterPassword, pwd) {
		SetMasterKey(nil)
		return model.PwdFile{}, ErrWrongMasterPassword
	}
	if err := upgradeKDFIfNeeded(&pwdObj, pwd, storeIter); err != nil {
		SetMasterKey(nil)
		return model.PwdFile{}, err
	}
	return pwdObj, nil
}
