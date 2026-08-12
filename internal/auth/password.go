package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters, calibrated per OWASP Password Storage Cheat Sheet and
// RFC 9106 second recommendation: 64 MiB memory, 3 iterations, 4 lanes.
// Parameters are stored inside each hash (PHC string format), so they can be
// raised later without invalidating existing hashes.
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 4
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// HashPassword derives an Argon2id hash and encodes it in PHC string format:
// $argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)

	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads, b64(salt), b64(key)), nil
}

// VerifyPassword reports whether password matches the PHC-encoded hash,
// recomputing with the parameters stored in the hash and comparing in
// constant time.
func VerifyPassword(password, encoded string) (bool, error) {
	salt, key, memory, time, threads, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	candidate := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(key)))
	return subtle.ConstantTimeCompare(candidate, key) == 1, nil
}

// dummyHash is verified against when a login names an unknown account, so
// the request costs the same Argon2id work as a real verification and
// response timing does not reveal whether a username exists.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := HashPassword("timing-equalization-dummy")
	if err != nil {
		panic(err)
	}
	return h
}

// EqualizeTiming burns the same Argon2id cost as a real password check.
func EqualizeTiming(password string) {
	_, _ = VerifyPassword(password, dummyHash)
}

func parsePHC(encoded string) (salt, key []byte, memory uint32, time uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, errors.New("auth: malformed password hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, nil, 0, 0, 0, errors.New("auth: unsupported hash version")
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || p > 255 {
		return nil, nil, 0, 0, 0, errors.New("auth: malformed hash parameters")
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, errors.New("auth: malformed salt")
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return nil, nil, 0, 0, 0, errors.New("auth: malformed hash")
	}
	return salt, key, m, t, uint8(p), nil
}
