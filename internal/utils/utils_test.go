/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
	"golang.org/x/crypto/pbkdf2"
)

func TestHashMasterPassword(t *testing.T) {
	password := []byte("master-password-test")
	hash1, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("HashMasterPassword failed: %v", err)
	}
	if !strings.HasPrefix(hash1, hashPrefix) {
		t.Fatalf("HashMasterPassword returned hash without prefix: %s", hash1)
	}

	hash2, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("HashMasterPassword failed: %v", err)
	}
	if hash1 == hash2 {
		t.Fatalf("HashMasterPassword should generate unique salts, got identical hashes: %s", hash1)
	}

	if !VerifyMasterPassword(hash1, password) {
		t.Fatalf("VerifyMasterPassword failed for generated hash1")
	}
	if !VerifyMasterPassword(hash2, password) {
		t.Fatalf("VerifyMasterPassword failed for generated hash2")
	}
}

func TestVerifyMasterPassword_PBKDF2(t *testing.T) {
	password := []byte("secret-master-password")
	hashed, err := HashMasterPassword(password)
	if err != nil {
		t.Fatalf("HashMasterPassword failed: %v", err)
	}

	if !VerifyMasterPassword(hashed, password) {
		t.Errorf("VerifyMasterPassword(%q, %q) = false, want true", hashed, password)
	}
	if VerifyMasterPassword(hashed, []byte("wrong-password")) {
		t.Errorf("VerifyMasterPassword with wrong password returned true, want false")
	}
}

func TestVerifyMasterPassword_LegacyFallback(t *testing.T) {
	rawDigestHex := fmt.Sprintf("%x", sha256.Sum256([]byte("legacy-secret-password")))
	tests := []struct {
		name      string
		stored    string
		candidate []byte
		want      bool
	}{
		{
			name:      "exact match on unprefixed plaintext password is rejected",
			stored:    "legacy-secret-password",
			candidate: []byte("legacy-secret-password"),
			want:      false,
		},
		{
			name:      "unprefixed single-pass sha256 digest is rejected",
			stored:    rawDigestHex,
			candidate: []byte("legacy-secret-password"),
			want:      false,
		},
		{
			name:      "unprefixed candidate matching digest string is rejected",
			stored:    rawDigestHex,
			candidate: []byte(rawDigestHex),
			want:      false,
		},
		{
			name:      "mismatched candidate on legacy plaintext password",
			stored:    "legacy-secret-password",
			candidate: []byte("different-password"),
			want:      false,
		},
		{
			name:      "empty stored password returns false",
			stored:    "",
			candidate: []byte("candidate"),
			want:      false,
		},
		{
			name:      "empty candidate with legacy stored returns false",
			stored:    "legacy-secret-password",
			candidate: []byte(""),
			want:      false,
		},
		{
			name:      "both stored and candidate empty returns false",
			stored:    "",
			candidate: []byte(""),
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyMasterPassword(tc.stored, tc.candidate)
			if got != tc.want {
				t.Errorf("VerifyMasterPassword(%q, %q) = %v, want %v", tc.stored, tc.candidate, got, tc.want)
			}
		})
	}
}

func TestVerifyMasterPassword_RejectsUnprefixedStrings(t *testing.T) {
	TestVerifyMasterPassword_LegacyFallback(t)
}

func TestPromptPasswordErr_NormalizesNilSlice(t *testing.T) {
	restore := SetReadPasswordStdin(func() ([]byte, error) {
		return nil, nil
	})
	defer restore()

	got, err := PromptPasswordErr("Enter password:")
	if err != nil {
		t.Fatalf("expected nil error from PromptPasswordErr, got %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil empty byte slice when reader returns (nil, nil), got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty byte slice, got %q", got)
	}
}

func TestVerifyMasterPassword_MalformedPBKDF2(t *testing.T) {
	password := []byte("secret-master-password")
	tests := []struct {
		name   string
		stored string
	}{
		{
			name:   "missing delimiter",
			stored: hashPrefix + "invalidsaltandkey",
		},
		{
			name:   "extra delimiter",
			stored: hashPrefix + "aa$bb$cc",
		},
		{
			name:   "empty salt part",
			stored: hashPrefix + "$aabbcc",
		},
		{
			name:   "empty dk part",
			stored: hashPrefix + "aabbcc$",
		},
		{
			name:   "invalid hex characters",
			stored: hashPrefix + "zzzz$zzzz",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyMasterPassword(tc.stored, password) {
				t.Errorf("VerifyMasterPassword(%q, %q) = true, want false", tc.stored, password)
			}
		})
	}
}

func TestVerifyMasterPassword_SingleByteDerivedKey(t *testing.T) {
	password := []byte("secret-master-password")
	salt := make([]byte, saltSize)
	oneByteDK := pbkdf2SHA256(password, salt, pbkdf2Iter, 1)
	singleByteRecord := fmt.Sprintf("%s%s$%s", hashPrefix, hex.EncodeToString(salt), hex.EncodeToString(oneByteDK))
	if VerifyMasterPassword(singleByteRecord, password) {
		t.Errorf("VerifyMasterPassword(%q, %q) = true, want false (accepted single-byte derived key)", singleByteRecord, password)
	}

	truncatedSalt := fmt.Sprintf("%s%s$%s", hashPrefix, "00", hex.EncodeToString(make([]byte, derivedKeySize)))
	if VerifyMasterPassword(truncatedSalt, password) {
		t.Errorf("VerifyMasterPassword(%q, %q) = true, want false (accepted truncated salt)", truncatedSalt, password)
	}
}

func TestPBKDF2SHA256_Equivalence(t *testing.T) {
	password := []byte("test-equivalence-password")
	salt := []byte("1234567890123456")
	iter := 100
	keyLen := 32
	got := pbkdf2SHA256(password, salt, iter, keyLen)
	wantCrypto := pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
	if !bytes.Equal(got, wantCrypto) {
		t.Errorf("pbkdf2SHA256 output does not match x/crypto/pbkdf2")
	}
	wantReused := pbkdf2SHA256ReusedHMAC(password, salt, iter, keyLen)
	if !bytes.Equal(got, wantReused) {
		t.Errorf("pbkdf2SHA256 output does not match pbkdf2SHA256ReusedHMAC")
	}
}

func pbkdf2SHA256ReusedHMAC(password, salt []byte, iter, keyLen int) []byte {
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

func withTempHome(t *testing.T) string {
	t.Helper()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Cleanup(func() {
		SetMasterKey(nil)
		_ = os.Chdir(origWd)
	})
	return tmpHome
}

func TestV2EncryptionLifecycle_RequiresMasterPasswordAndRemovesKeyFile(t *testing.T) {
	tmpHome := withTempHome(t)
	masterSecret := []byte("correct-horse-battery-staple")
	hashed, err := HashMasterPassword(masterSecret)
	if err != nil {
		t.Fatalf("HashMasterPassword: %v", err)
	}

	legacyKeyPath := filepath.Join(tmpHome, PwdFileKey)
	if err := os.WriteFile(legacyKeyPath, bytes.Repeat([]byte{"k"[0]}, 32), 0600); err != nil {
		t.Fatalf("write legacy key file: %v", err)
	}

	SetMasterKey(masterSecret)
	if err := SaveFileErr(model.PwdFile{MasterPassword: hashed}, nil); err != nil {
		t.Fatalf("SaveFileErr failed: %v", err)
	}

	if _, err := os.Stat(legacyKeyPath); !os.IsNotExist(err) {
		t.Fatalf("expected plaintext key file %s to be removed after v2 encryption, stat err: %v", legacyKeyPath, err)
	}

	rawStore, err := os.ReadFile(filepath.Join(tmpHome, PwdFileName))
	if err != nil {
		t.Fatalf("read encrypted store: %v", err)
	}
	if !bytes.HasPrefix(rawStore, []byte(v2Magic)) {
		t.Fatalf("expected encrypted store to start with %q magic header", v2Magic)
	}

	SetMasterKey(nil)
	if _, err := GetPwdObj(); err == nil || !strings.Contains(err.Error(), "master password required") {
		t.Fatalf("expected decryption without master password to fail with 'master password required', got %v", err)
	}

	SetMasterKey([]byte("wrong-master-password"))
	if _, err := GetPwdObj(); err == nil || !errors.Is(err, errDecryptFailed) {
		t.Fatalf("expected decryption with wrong master password to fail with errDecryptFailed, got %v", err)
	}

	SetMasterKey(masterSecret)
	got, err := GetPwdObj()
	if err != nil {
		t.Fatalf("GetPwdObj with correct master password failed: %v", err)
	}
	if got.MasterPassword != hashed {
		t.Fatalf("GetPwdObj MasterPassword = %q, want %q", got.MasterPassword, hashed)
	}
}

func TestGetPwdObjAfterCheckMaster_PromptsBeforeDecryptAndRejectsWrongPassword(t *testing.T) {
	withTempHome(t)
	masterSecret := []byte("vault-master-secret")
	hashed, err := HashMasterPassword(masterSecret)
	if err != nil {
		t.Fatalf("HashMasterPassword: %v", err)
	}

	SetMasterKey(masterSecret)
	if err := SaveFileErr(model.PwdFile{MasterPassword: hashed}, nil); err != nil {
		t.Fatalf("SaveFileErr: %v", err)
	}
	SetMasterKey(nil)

	exited := false
	restoreExit := SetExitFunc(func(code int) {
		exited = true
	})
	defer restoreExit()

	restoreStdin := SetReadPasswordStdin(func() ([]byte, error) {
		return []byte("wrong-password"), nil
	})
	defer restoreStdin()

	_, err = GetPwdObjAfterCheckMaster()
	if err == nil || !strings.Contains(err.Error(), "master passwords do not match") {
		t.Fatalf("expected master passwords do not match error, got %v", err)
	}
	if exited {
		t.Fatalf("expected wrong master password not to invoke exitFunc")
	}
	if getMasterKey() != nil {
		t.Fatalf("expected session master key to be cleared after failed verification")
	}

	restoreStdinCorrect := SetReadPasswordStdin(func() ([]byte, error) {
		return masterSecret, nil
	})
	defer restoreStdinCorrect()

	pwdObj, err := GetPwdObjAfterCheckMaster()
	if err != nil {
		t.Fatalf("GetPwdObjAfterCheckMaster with valid password failed: %v", err)
	}
	if pwdObj.MasterPassword != hashed {
		t.Fatalf("unexpected MasterPassword hash: got %q, want %q", pwdObj.MasterPassword, hashed)
	}
	if !bytes.Equal(getMasterKey(), masterSecret) {
		t.Fatalf("expected session master key to remain set after successful unlock")
	}
}

func TestGetPwdObjAfterCheckMaster_RejectsMismatchedStoredHash(t *testing.T) {
	withTempHome(t)
	encryptionSecret := []byte("encryption-secret")
	otherHash, err := HashMasterPassword([]byte("different-stored-hash-secret"))
	if err != nil {
		t.Fatalf("HashMasterPassword: %v", err)
	}

	SetMasterKey(encryptionSecret)
	if err := SaveFileErr(model.PwdFile{MasterPassword: otherHash}, nil); err != nil {
		t.Fatalf("SaveFileErr: %v", err)
	}
	SetMasterKey(nil)

	restoreStdin := SetReadPasswordStdin(func() ([]byte, error) {
		return encryptionSecret, nil
	})
	defer restoreStdin()

	if _, err := GetPwdObjAfterCheckMaster(); err == nil || !strings.Contains(err.Error(), "master passwords do not match") {
		t.Fatalf("expected mismatch error when stored hash differs from encryption secret, got %v", err)
	}
	if getMasterKey() != nil {
		t.Fatalf("expected session master key to be cleared when VerifyMasterPassword fails")
	}
}

func TestDecryptV2_BoundaryInputs(t *testing.T) {
	SetMasterKey([]byte("boundary-test-secret"))
	defer SetMasterKey(nil)

	if _, err := decryptV2(make([]byte, saltSize-1)); err == nil || !strings.Contains(err.Error(), "ciphertext too short") {
		t.Fatalf("expected ciphertext too short for payload smaller than saltSize, got %v", err)
	}

	if _, err := decryptV2(make([]byte, saltSize+4)); err == nil || !strings.Contains(err.Error(), "ciphertext too short") {
		t.Fatalf("expected ciphertext too short for payload with truncated GCM nonce, got %v", err)
	}
}

func TestSetMasterKey_IsolationAndClear(t *testing.T) {
	raw := []byte("mutable-secret")
	SetMasterKey(raw)
	raw[0] = 'X'

	got := getMasterKey()
	if string(got) != "mutable-secret" {
		t.Fatalf("expected SetMasterKey to copy input slice, got %q", got)
	}
	got[0] = 'Y'
	if string(getMasterKey()) != "mutable-secret" {
		t.Fatalf("expected getMasterKey to return a copy, got %q", getMasterKey())
	}

	SetMasterKey([]byte{})
	if getMasterKey() != nil {
		t.Fatalf("expected empty slice to clear session master key, got %v", getMasterKey())
	}
}

func TestFileOperations_PreserveWorkingDirAndEnforcePermissions(t *testing.T) {
	tmpHome := withTempHome(t)
	workDir := t.TempDir()
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir workDir: %v", err)
	}
	expectedWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	masterSecret := []byte("cwd-and-perm-secret")
	hashed, err := HashMasterPassword(masterSecret)
	if err != nil {
		t.Fatalf("HashMasterPassword: %v", err)
	}
	SetMasterKey(masterSecret)

	if err := SaveFileErr(model.PwdFile{MasterPassword: hashed}, nil); err != nil {
		t.Fatalf("SaveFileErr: %v", err)
	}

	afterSaveWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd after save: %v", err)
	}
	if afterSaveWd != expectedWd {
		t.Fatalf("SaveFileErr changed working directory: got %q, want %q", afterSaveWd, expectedWd)
	}

	storePath := filepath.Join(tmpHome, PwdFileName)
	fi, err := os.Lstat(storePath)
	if err != nil {
		t.Fatalf("lstat store: %v", err)
	}
	if gotPerm := fi.Mode().Perm(); gotPerm != sensitivePerm {
		t.Fatalf("store file permissions = %04o, want %04o", gotPerm, sensitivePerm)
	}

	entries, err := os.ReadDir(tmpHome)
	if err != nil {
		t.Fatalf("readdir home: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != PwdFileName {
		t.Fatalf("unexpected files in home dir after atomic write: %v", entries)
	}

	restoreStdin := SetReadPasswordStdin(func() ([]byte, error) {
		return masterSecret, nil
	})
	defer restoreStdin()

	if _, err := GetPwdObjAfterCheckMaster(); err != nil {
		t.Fatalf("GetPwdObjAfterCheckMaster: %v", err)
	}
	afterReadWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd after read: %v", err)
	}
	if afterReadWd != expectedWd {
		t.Fatalf("GetPwdObjAfterCheckMaster changed working directory: got %q, want %q", afterReadWd, expectedWd)
	}
}

func assertStoreSymlinkRejected(t *testing.T, storePath, externalTarget string) {
	t.Helper()
	if err := os.Symlink(externalTarget, storePath); err != nil {
		t.Fatalf("symlink store: %v", err)
	}
	defer func() {
		_ = os.Remove(storePath)
	}()

	SetMasterKey([]byte("symlink-test-secret"))
	if err := SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); !errors.Is(err, ErrSymlink) {
		t.Fatalf("expected SaveFileErr on symlink store to fail with ErrSymlink, got %v", err)
	}

	externalContent, err := os.ReadFile(externalTarget)
	if err != nil {
		t.Fatalf("read external target: %v", err)
	}
	if string(externalContent) != "original-external-content" {
		t.Fatalf("symlink target was modified: got %q", externalContent)
	}

	if _, err := GetPwdObj(); !errors.Is(err, ErrSymlink) {
		t.Fatalf("expected GetPwdObj on symlink store to fail with ErrSymlink, got %v", err)
	}

	exited := false
	restoreExit := SetExitFunc(func(code int) {
		exited = true
	})
	defer restoreExit()
	if _, err := GetPwdObjAfterCheckMaster(); !errors.Is(err, ErrSymlink) || !exited {
		t.Fatalf("expected GetPwdObjAfterCheckMaster on symlink store to exit and return ErrSymlink, got err=%v exited=%v", err, exited)
	}
}

func assertStoreNonRegularRejected(t *testing.T, storePath string) {
	t.Helper()
	if err := os.Mkdir(storePath, 0700); err != nil {
		t.Fatalf("mkdir store path: %v", err)
	}
	defer func() {
		_ = os.Remove(storePath)
	}()

	SetMasterKey([]byte("nonregular-test-secret"))
	if err := SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); !errors.Is(err, ErrNonRegular) {
		t.Fatalf("expected SaveFileErr on directory store path to fail with ErrNonRegular, got %v", err)
	}
	if _, err := GetPwdObj(); !errors.Is(err, ErrNonRegular) {
		t.Fatalf("expected GetPwdObj on directory store path to fail with ErrNonRegular, got %v", err)
	}
}

func assertKeySymlinkRejected(t *testing.T, keyPath, externalTarget string) {
	t.Helper()
	if err := os.Symlink(externalTarget, keyPath); err != nil {
		t.Fatalf("symlink key file: %v", err)
	}
	defer func() {
		_ = os.Remove(keyPath)
	}()

	SetMasterKey([]byte("symlink-key-secret"))
	if err := SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); !errors.Is(err, ErrSymlink) {
		t.Fatalf("expected v2 SaveFileErr to refuse removing symlink key file with ErrSymlink, got %v", err)
	}

	SetMasterKey(nil)
	if err := SaveFileErr(model.PwdFile{MasterPassword: "hash"}, nil); !errors.Is(err, ErrSymlink) {
		t.Fatalf("expected legacy SaveFileErr to refuse reading symlink key file with ErrSymlink, got %v", err)
	}
}

func TestSensitiveFileOperations_RejectSymlinksAndNonRegularFiles(t *testing.T) {
	tmpHome := withTempHome(t)
	targetDir := t.TempDir()
	externalTarget := filepath.Join(targetDir, "target-file")
	if err := os.WriteFile(externalTarget, []byte("original-external-content"), 0600); err != nil {
		t.Fatalf("write external target: %v", err)
	}

	storePath := filepath.Join(tmpHome, PwdFileName)
	assertStoreSymlinkRejected(t, storePath, externalTarget)
	assertStoreNonRegularRejected(t, storePath)

	keyPath := filepath.Join(tmpHome, PwdFileKey)
	assertKeySymlinkRejected(t, keyPath, externalTarget)
}

func TestResolveHomePath_BoundaryInputs(t *testing.T) {
	tmpHome := withTempHome(t)

	for _, invalid := range []string{"", "../evil", "sub/file", "/abs/path"} {
		if _, err := resolveHomePath(invalid); err == nil {
			t.Fatalf("expected resolveHomePath(%q) to fail, got nil", invalid)
		}
	}

	got, err := resolveHomePath(PwdFileName)
	if err != nil {
		t.Fatalf("resolveHomePath(%q) failed: %v", PwdFileName, err)
	}
	absHome, err := filepath.Abs(tmpHome)
	if err != nil {
		t.Fatalf("abs home: %v", err)
	}
	want := filepath.Join(absHome, PwdFileName)
	if got != want {
		t.Fatalf("resolveHomePath(%q) = %q, want %q", PwdFileName, got, want)
	}
}

func BenchmarkPBKDF2SHA256(b *testing.B) {
	password := []byte("benchmark-password")
	salt := make([]byte, saltSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2SHA256(password, salt, 1000, derivedKeySize)
	}
}

func BenchmarkPBKDF2SHA256_ReusedHMAC(b *testing.B) {
	password := []byte("benchmark-password")
	salt := make([]byte, saltSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2SHA256ReusedHMAC(password, salt, 1000, derivedKeySize)
	}
}

func BenchmarkPBKDF2SHA256_CryptoPBKDF2(b *testing.B) {
	password := []byte("benchmark-password")
	salt := make([]byte, saltSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2.Key(password, salt, 1000, derivedKeySize, sha256.New)
	}
}
