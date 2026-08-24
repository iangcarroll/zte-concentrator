// blobcrypt encrypts and decrypts the proprietary device binary so it can live
// in the repository without the repository containing a usable copy of it.
//
// The point is narrow and worth stating: `emu/` needs the device's real
// zte_icg_agg to be useful, and CI needs it to prove the concentrator works
// against the real client rather than against a client written from the same
// notes. But committing ZTE's binary would mean the
// repository distributes it, which is not ours to do.
// Encrypting it means the repository holds ciphertext, the key lives only in a
// GitHub Actions secret, and the plaintext exists only in a runner's memory and
// on machines that already had it.
//
//	go run ./emu/blobcrypt -e -in zte_icg_agg  -out emu/blobs/zte_icg_agg.enc
//	go run ./emu/blobcrypt -d -in emu/blobs/zte_icg_agg.enc -out /tmp/zte_icg_agg
//
// The key comes from $ICG_BLOB_KEY, or stdin if that is unset.
//
// AES-256-GCM, so tampering is detected rather than producing garbage that
// looks like a binary. The key is stretched with PBKDF2-SHA256 — stdlib only,
// no dependencies, which matters because this has to run identically on a
// laptop and on a runner with nothing installed.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// The container format. Versioned so a future change to the KDF or cipher can
// be detected rather than mis-decrypted.
const (
	magic     = "ICGBLOB1"
	saltLen   = 16
	nonceLen  = 12
	keyLen    = 32
	iterCount = 600_000 // ~0.3 s; irrelevant for a random key, useful for a weak one
)

func main() {
	var (
		enc    = flag.Bool("e", false, "encrypt")
		dec    = flag.Bool("d", false, "decrypt")
		in     = flag.String("in", "", "input file (default stdin)")
		out    = flag.String("out", "", "output file (default stdout)")
		keygen = flag.Bool("keygen", false, "print a fresh random key and exit")
	)
	flag.Parse()

	if *keygen {
		// 32 random bytes, base64 — long enough that the KDF is belt and braces.
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fatal("generating a key: %v", err)
		}
		fmt.Println(b64(b))
		return
	}
	if *enc == *dec {
		fatal("give exactly one of -e or -d (or -keygen)")
	}

	key, err := readKey()
	if err != nil {
		fatal("%v", err)
	}

	data, err := readAll(*in)
	if err != nil {
		fatal("reading input: %v", err)
	}

	var result []byte
	if *enc {
		result, err = encrypt(key, data)
	} else {
		result, err = decrypt(key, data)
	}
	if err != nil {
		fatal("%v", err)
	}
	if err := writeAll(*out, result); err != nil {
		fatal("writing output: %v", err)
	}
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	gcm, err := aead(key, salt)
	if err != nil {
		return nil, err
	}
	// The header is authenticated as additional data, so a truncated or edited
	// header fails the tag check instead of decrypting to nonsense.
	header := append(append([]byte(magic), salt...), nonce...)
	return gcm.Seal(header, nonce, plaintext, header), nil
}

func decrypt(key, blob []byte) ([]byte, error) {
	// Magic first: "you handed me the plaintext" is by far the most likely
	// mistake here, and it deserves the better message even when the input is
	// also too short.
	if !bytes.HasPrefix(blob, []byte(magic)) {
		return nil, fmt.Errorf("bad magic: this is not a %s blob "+
			"(is it the plaintext binary by mistake?)", magic)
	}
	hdrLen := len(magic) + saltLen + nonceLen
	if len(blob) < hdrLen+16 {
		return nil, errors.New("input is too short to be an encrypted blob")
	}
	salt := blob[len(magic) : len(magic)+saltLen]
	nonce := blob[len(magic)+saltLen : hdrLen]
	gcm, err := aead(key, salt)
	if err != nil {
		return nil, err
	}
	out, err := gcm.Open(nil, nonce, blob[hdrLen:], blob[:hdrLen])
	if err != nil {
		return nil, errors.New("decryption failed: wrong key, or the blob was modified")
	}
	return out, nil
}

func aead(key, salt []byte) (cipher.AEAD, error) {
	dk, err := pbkdf2.Key(sha256.New, string(key), salt, iterCount, keyLen)
	if err != nil {
		return nil, fmt.Errorf("kdf: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// readKey takes the key from the environment, or stdin when -in is a file.
func readKey() ([]byte, error) {
	if k := os.Getenv("ICG_BLOB_KEY"); k != "" {
		return []byte(strings.TrimSpace(k)), nil
	}
	fmt.Fprintln(os.Stderr, "blobcrypt: $ICG_BLOB_KEY is unset, reading the key from stdin")
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading the key from stdin: %w", err)
	}
	k := bytes.TrimSpace(b)
	if len(k) == 0 {
		return nil, errors.New("no key: set $ICG_BLOB_KEY or pipe one in")
	}
	return k, nil
}

func readAll(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeAll(path string, b []byte) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(b)
		return err
	}
	// 0600: if this is the decrypted binary, it is nobody else's business.
	return os.WriteFile(path, b, 0o600)
}

func b64(b []byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		sb.WriteByte(alpha[(n>>18)&63])
		sb.WriteByte(alpha[(n>>12)&63])
		if rem > 1 {
			sb.WriteByte(alpha[(n>>6)&63])
		}
		if rem > 2 {
			sb.WriteByte(alpha[n&63])
		}
	}
	return sb.String()
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "blobcrypt: "+format+"\n", a...)
	os.Exit(1)
}
