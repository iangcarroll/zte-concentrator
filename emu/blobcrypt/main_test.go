package main

import (
	"bytes"
	"strings"
	"testing"
)

var key = []byte("a-test-key-with-plenty-of-entropy")

func TestRoundTrip(t *testing.T) {
	// An ELF header, so the test exercises the shape of the thing we actually
	// encrypt rather than a short string.
	plain := append([]byte("\x7fELF\x02\x01\x01"), bytes.Repeat([]byte("payload"), 5000)...)

	blob, err := encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("\x7fELF")) {
		t.Fatal("the ciphertext still contains an ELF magic; that defeats the whole point")
	}
	if !bytes.HasPrefix(blob, []byte(magic)) {
		t.Fatalf("blob does not start with %q", magic)
	}

	got, err := decrypt(key, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip did not return the input")
	}
}

// Encrypting twice must not produce the same bytes, or committing a re-encrypted
// blob would leak that nothing changed — and worse, a repeated nonce with the
// same derived key would be catastrophic for GCM.
func TestEncryptIsNotDeterministic(t *testing.T) {
	a, err := encrypt(key, []byte("same input"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := encrypt(key, []byte("same input"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same input are identical: salt or nonce is not random")
	}
	hdr := len(magic) + saltLen + nonceLen
	if bytes.Equal(a[len(magic):hdr], b[len(magic):hdr]) {
		t.Fatal("salt+nonce repeated across encryptions")
	}
}

func TestWrongKeyFails(t *testing.T) {
	blob, err := encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decrypt([]byte("not the key"), blob); err == nil {
		t.Fatal("decryption with the wrong key succeeded")
	}
}

// GCM is used precisely so a modified blob is rejected rather than yielding a
// plausible-looking binary.
func TestTamperingIsDetected(t *testing.T) {
	blob, err := encrypt(key, bytes.Repeat([]byte("x"), 1000))
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{0, len(magic), len(magic) + 2, len(blob) / 2, len(blob) - 1} {
		bad := append([]byte(nil), blob...)
		bad[at] ^= 0xff
		if _, err := decrypt(key, bad); err == nil {
			t.Errorf("flipping byte %d was not detected", at)
		}
	}
}

func TestRejectsPlaintextInput(t *testing.T) {
	_, err := decrypt(key, []byte("\x7fELF\x02\x01\x01 not encrypted at all"))
	if err == nil {
		t.Fatal("decrypting a plaintext ELF succeeded")
	}
	// The message has to say what the likely mistake was, because this is the
	// error someone gets when they forget to encrypt.
	if !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("unhelpful error for plaintext input: %v", err)
	}
}

func TestRejectsTruncated(t *testing.T) {
	blob, err := encrypt(key, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, len(magic), len(blob) - 1} {
		if _, err := decrypt(key, blob[:n]); err == nil {
			t.Errorf("a %d-byte input was accepted", n)
		}
	}
}

func TestKeygenIsBase64AndLongEnough(t *testing.T) {
	// 32 random bytes -> 43 base64url chars. A short key here would silently
	// weaken every blob.
	s := b64(bytes.Repeat([]byte{0xab}, 32))
	if len(s) != 43 {
		t.Fatalf("b64 of 32 bytes is %d chars, want 43", len(s))
	}
	for _, c := range s {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", c) {
			t.Fatalf("non-base64url character %q", c)
		}
	}
}
