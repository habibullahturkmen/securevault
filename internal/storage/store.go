// Package storage implements SecureVault's content-addressed storage engine.
//
// Every stored object is identified by the SHA-256 hash of its plaintext
// content. Before touching disk, content is encrypted with AES-256-GCM under
// a fresh per-object data-encryption key (DEK); the DEK is wrapped by the
// store's master key (KEK) and returned to the caller for persistence in the
// metadata database. The content hash is used as GCM associated data for both
// the object and the wrapped DEK, so ciphertext cannot be relocated to a
// different content address without failing authentication.
//
// Writes are two-phase and atomic:
//
//	staged, _ := store.Stage(r, limit)   // stream, enforce limit, hash, encrypt to temp
//	// caller checks its metadata DB for staged.Hash:
//	//   row exists  -> staged.Abort()  (dedup: keep existing object and DEK)
//	//   row missing -> staged.Commit() (fsync + rename), then commit the DB row
//	//
//
// Committing the file before the database row means a crash can only produce
// an orphan object file (invisible, replaced by the next upload of the same
// content) — never a database row pointing at a missing or partial object.
//
// Reads verify before releasing a single byte: GCM tag verification during
// decryption, then SHA-256 re-verification of the plaintext against the
// requested content address. Corruption yields ErrCorrupt, never plaintext.
package storage

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// HashSize is the length of a content address (SHA-256).
const HashSize = sha256.Size

var (
	// ErrNotFound reports that no object exists for the given content address.
	ErrNotFound = errors.New("storage: object not found")
	// ErrCorrupt reports that an object failed integrity verification.
	// The plaintext is never returned alongside this error.
	ErrCorrupt = errors.New("storage: object failed integrity verification")
	// ErrTooLarge reports that the streamed content exceeded the size limit.
	ErrTooLarge = errors.New("storage: content exceeds size limit")
)

// objMagic prefixes every object file, followed by the 12-byte content nonce
// and the AES-256-GCM ciphertext (which includes the 16-byte tag).
var objMagic = []byte("SVL1")

// Store is a content-addressed, encrypted object store rooted at a directory.
// It is safe for concurrent use.
type Store struct {
	root string
	kek  []byte
}

// New opens (creating if necessary) a store rooted at dir. kek must be a
// 32-byte AES-256 key. The temp directory lives inside the root so renames
// stay on one filesystem and remain atomic.
func New(dir string, kek []byte) (*Store, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("storage: master key must be 32 bytes, got %d", len(kek))
	}
	for _, sub := range []string{"objects", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("storage: create %s dir: %w", sub, err)
		}
	}
	k := make([]byte, 32)
	copy(k, kek)
	return &Store{root: dir, kek: k}, nil
}

// Staged is content that has been received, hashed, and encrypted to a
// temporary file but not yet made visible. Exactly one of Commit or Abort
// must be called.
type Staged struct {
	// Hash is the SHA-256 content address of the plaintext.
	Hash [HashSize]byte
	// Size is the plaintext length in bytes.
	Size int64
	// WrappedDEK is the object's data-encryption key, encrypted under the
	// store's master key. The caller persists it in the metadata database;
	// it is required to Open the object later.
	WrappedDEK []byte

	store   *Store
	tmpPath string
	done    bool
}

// Stage streams content from r, enforcing limit bytes while receiving.
// It computes the content hash, generates a fresh DEK and nonce, encrypts,
// and writes the ciphertext to a temporary file inside the store.
// On any error the temporary file is removed.
func (s *Store) Stage(r io.Reader, limit int64) (*Staged, error) {
	if limit <= 0 {
		return nil, errors.New("storage: limit must be positive")
	}

	// Read at most limit+1 bytes: seeing the extra byte proves the stream
	// exceeds the limit without buffering the remainder.
	plaintext, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("storage: receive content: %w", err)
	}
	if int64(len(plaintext)) > limit {
		return nil, ErrTooLarge
	}

	hash := sha256.Sum256(plaintext)

	dek, err := newDEK()
	if err != nil {
		return nil, err
	}
	wrapped, err := wrapDEK(s.kek, dek, hash[:])
	if err != nil {
		return nil, err
	}
	nonce, sealed, err := encrypt(dek, plaintext, hash[:])
	if err != nil {
		return nil, err
	}

	tmp, err := os.CreateTemp(filepath.Join(s.root, "tmp"), "staged-*")
	if err != nil {
		return nil, fmt.Errorf("storage: create temp file: %w", err)
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}

	for _, part := range [][]byte{objMagic, nonce, sealed} {
		if _, err := tmp.Write(part); err != nil {
			cleanup()
			return nil, fmt.Errorf("storage: write temp file: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return nil, fmt.Errorf("storage: fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("storage: close temp file: %w", err)
	}

	return &Staged{
		Hash:       hash,
		Size:       int64(len(plaintext)),
		WrappedDEK: wrapped,
		store:      s,
		tmpPath:    tmp.Name(),
	}, nil
}

// Commit atomically publishes the staged object at its content address,
// replacing any existing file there (only correct when the caller is
// creating the first metadata reference; see the package comment).
// The object file and its directory are fsynced before rename returns.
func (st *Staged) Commit() error {
	if st.done {
		return errors.New("storage: staged object already finalized")
	}
	st.done = true

	dst := st.store.objectPath(st.Hash[:])
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		os.Remove(st.tmpPath)
		return fmt.Errorf("storage: create object dir: %w", err)
	}
	if err := os.Rename(st.tmpPath, dst); err != nil {
		os.Remove(st.tmpPath)
		return fmt.Errorf("storage: publish object: %w", err)
	}
	// fsync the containing directory so the rename itself survives a crash.
	if dir, err := os.Open(filepath.Dir(dst)); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

// Abort discards the staged temporary file. Used on deduplication hits and
// on any failure after staging.
func (st *Staged) Abort() {
	if st.done {
		return
	}
	st.done = true
	os.Remove(st.tmpPath)
}

// Open retrieves, decrypts, and fully verifies the object at the given
// content address. It returns the plaintext only after both the AES-GCM
// authentication tag and the SHA-256 re-hash against hash succeed; any
// failure returns ErrCorrupt with no plaintext.
func (s *Store) Open(hash []byte, wrappedDEK []byte) ([]byte, error) {
	if len(hash) != HashSize {
		return nil, fmt.Errorf("storage: content address must be %d bytes", HashSize)
	}

	raw, err := os.ReadFile(s.objectPath(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: read object: %w", err)
	}

	if len(raw) < len(objMagic)+nonceSize || !bytes.Equal(raw[:len(objMagic)], objMagic) {
		return nil, fmt.Errorf("%w: malformed object header", ErrCorrupt)
	}
	nonce := raw[len(objMagic) : len(objMagic)+nonceSize]
	sealed := raw[len(objMagic)+nonceSize:]

	dek, err := unwrapDEK(s.kek, wrappedDEK, hash)
	if err != nil {
		return nil, fmt.Errorf("%w: key unwrap failed", ErrCorrupt)
	}

	plaintext, err := decrypt(dek, nonce, sealed, hash)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication tag mismatch", ErrCorrupt)
	}

	// Defense in depth: the content address is re-verified even though the
	// GCM tag (with the hash as associated data) already authenticated the
	// ciphertext. This is the store's tamper-evidence contract.
	sum := sha256.Sum256(plaintext)
	if subtle.ConstantTimeCompare(sum[:], hash) != 1 {
		return nil, fmt.Errorf("%w: content hash mismatch", ErrCorrupt)
	}

	return plaintext, nil
}

// Exists reports whether an object file is present for the content address.
// Presence of the file says nothing about references; the metadata database
// is the source of truth for visibility.
func (s *Store) Exists(hash []byte) bool {
	_, err := os.Stat(s.objectPath(hash))
	return err == nil
}

// Remove deletes the object file for the content address. The caller must
// only invoke it after the last metadata reference is gone (ref_count == 0).
// A missing file is not an error: a crash between the metadata commit and
// Remove leaves an orphan, and re-deletion must be idempotent.
func (s *Store) Remove(hash []byte) error {
	err := os.Remove(s.objectPath(hash))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("storage: remove object: %w", err)
	}
	return nil
}

// objectPath maps a content address to its file path with a two-character
// fan-out directory. The path is derived exclusively from the hash — user
// input never influences a filesystem path.
func (s *Store) objectPath(hash []byte) string {
	h := hex.EncodeToString(hash)
	return filepath.Join(s.root, "objects", h[:2], h+".obj")
}
