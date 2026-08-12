package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// tokenBytes is the entropy of a session token: 256 bits.
const tokenBytes = 32

// NewSessionToken returns an opaque random token for the client cookie and
// the SHA-256 hash under which it is stored. The plaintext token exists only
// in the cookie; a database leak reveals nothing reusable.
func NewSessionToken() (token string, hash []byte, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("auth: generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken maps a client-presented token to its storage hash.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
