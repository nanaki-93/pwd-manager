/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package utils

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

const encryptTestPayloadBytes = 1 << 20

func v3TestPrefix(salt []byte) []byte {
	prefix := append([]byte(v3Magic), binary.BigEndian.AppendUint32(nil, uint32(pbkdf2Iter))...)
	return append(prefix, salt...)
}

func encryptTestPayload() []byte {
	payload := make([]byte, encryptTestPayloadBytes)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

func TestEncryptFileWithRawKey_RoundTripsLargePayload(t *testing.T) {
	withTempHome(t)
	secret := []byte("large-payload-secret")
	salt := bytes.Repeat([]byte{0x42}, saltSize)
	key := deriveEncryptionKey(secret, salt, pbkdf2Iter)
	payload := encryptTestPayload()
	if err := encryptFileWithRawKey(payload, key, v3TestPrefix(salt)); err != nil {
		t.Fatalf("encryptFileWithRawKey: %v", err)
	}
	SetMasterKey(secret)
	got, err := readPwdFile()
	if err != nil {
		t.Fatalf("readPwdFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decrypted payload mismatch (len %d, want %d)", len(got), len(payload))
	}
}

// A single save must allocate the ciphertext once; the old Seal-then-prefix
// path allocated it twice (about 2 MB for a 1 MB payload).
func TestEncryptFileWithRawKey_AllocatesCiphertextOnce(t *testing.T) {
	withTempHome(t)
	key := bytes.Repeat([]byte{0x07}, derivedKeySize)
	prefix := v3TestPrefix(bytes.Repeat([]byte{0x42}, saltSize))
	payload := encryptTestPayload()
	if err := encryptFileWithRawKey(payload, key, prefix); err != nil {
		t.Fatalf("warm-up encryptFileWithRawKey: %v", err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if err := encryptFileWithRawKey(payload, key, prefix); err != nil {
		t.Fatalf("encryptFileWithRawKey: %v", err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(encryptTestPayloadBytes * 3 / 2); allocated > limit {
		t.Fatalf("encryptFileWithRawKey allocated %d bytes for a 1 MB payload, want <= %d", allocated, limit)
	}
}

func BenchmarkEncryptFileWithRawKey(b *testing.B) {
	b.Setenv("HOME", b.TempDir())
	key := bytes.Repeat([]byte{0x07}, derivedKeySize)
	prefix := v3TestPrefix(bytes.Repeat([]byte{0x42}, saltSize))
	payload := encryptTestPayload()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := encryptFileWithRawKey(payload, key, prefix); err != nil {
			b.Fatalf("encryptFileWithRawKey: %v", err)
		}
	}
}
