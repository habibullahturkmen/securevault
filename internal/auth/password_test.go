package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Errorf("unexpected PHC prefix: %s", hash[:40])
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("correct password rejected: ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("wrong password accepted")
	}
}

func TestUniqueSalts(t *testing.T) {
	h1, _ := HashPassword("same password")
	h2, _ := HashPassword("same password")
	if h1 == h2 {
		t.Error("two hashes of the same password are identical — salt reuse")
	}
}

func TestMalformedHashRejected(t *testing.T) {
	malformed := []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",       // wrong variant
		"$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$aGFzaA",      // wrong version
		"$argon2id$v=19$m=0,t=0,p=0$c2FsdA$aGFzaA",          // zero params
		"$argon2id$v=19$m=65536,t=3,p=4$!!badsalt!!$aGFzaA", // bad base64
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$",            // empty hash
	}
	for _, h := range malformed {
		if ok, err := VerifyPassword("password", h); err == nil || ok {
			t.Errorf("malformed hash %q: ok=%v err=%v, want error", h, ok, err)
		}
	}
}

func TestSessionTokens(t *testing.T) {
	t1, h1, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	t2, h2, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}

	if t1 == t2 {
		t.Fatal("two session tokens are identical")
	}
	if len(h1) != 32 || len(h2) != 32 {
		t.Errorf("token hash length = %d, want 32", len(h1))
	}
	if string(HashToken(t1)) != string(h1) {
		t.Error("HashToken(token) does not match stored hash")
	}
	if strings.Contains(t1, string(h1)) {
		t.Error("plaintext token embeds its own hash")
	}
}
