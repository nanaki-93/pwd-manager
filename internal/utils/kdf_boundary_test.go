package utils

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/nanaki-93/pwd-manager/internal/model"
)

func TestHashNeedsUpgradeValidationBoundaries(t *testing.T) {
	salt := strings.Repeat("01", saltSize)
	digest := strings.Repeat("02", derivedKeySize)
	format := func(iter int, s, d string) string {
		return fmt.Sprintf("%s%d$%s$%s", hashPrefix, iter, s, d)
	}
	cases := []struct {
		name, hash string
		want       bool
	}{
		{"minimum", format(legacyPBKDF2Iter, salt, digest), true},
		{"just weaker", format(pbkdf2Iter-1, salt, digest), true},
		{"current", format(pbkdf2Iter, salt, digest), false},
		{"just stronger", format(pbkdf2Iter+1, salt, digest), false},
		{"maximum", format(maxPBKDF2Iter, salt, digest), false},
		{"below minimum", format(legacyPBKDF2Iter-1, salt, digest), false},
		{"above maximum", format(maxPBKDF2Iter+1, salt, digest), false},
		{"negative", format(-1, salt, digest), false},
		{"short salt", format(legacyPBKDF2Iter, salt[2:], digest), false},
		{"short digest", format(legacyPBKDF2Iter, salt, digest[2:]), false},
		{"invalid hex", format(legacyPBKDF2Iter, strings.Repeat("zz", saltSize), digest), false},
		{"extra field", format(legacyPBKDF2Iter, salt, digest) + "$extra", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hashNeedsUpgrade(tc.hash); got != tc.want {
				t.Fatalf("hashNeedsUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUpgradeKDFHigherStoreCurrentHashIsNoOp(t *testing.T) {
	home := withTempHome(t)
	// A current hash needs no rehash even when the store uses a stronger KDF.
	hash := fmt.Sprintf("%s%d$%s$%s", hashPrefix, pbkdf2Iter,
		strings.Repeat("01", saltSize), strings.Repeat("02", derivedKeySize))
	obj := model.PwdFile{MasterPassword: hash}
	if err := upgradeKDFIfNeeded(&obj, []byte("unused"), testHigherPBKDF2Iter); err != nil {
		t.Fatalf("no-op upgrade: %v", err)
	}
	if obj.MasterPassword != hash {
		t.Fatal("no-op upgrade changed hash")
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("no-op upgrade wrote files: %v", entries)
	}
}
