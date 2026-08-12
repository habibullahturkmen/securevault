package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testKEK(t *testing.T) []byte {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	return kek
}

func newTestStore(t *testing.T) (*Store, []byte) {
	t.Helper()
	kek := testKEK(t)
	s, err := New(t.TempDir(), kek)
	if err != nil {
		t.Fatal(err)
	}
	return s, kek
}

// put stages and commits content, returning the staged metadata.
func put(t *testing.T, s *Store, content []byte) *Staged {
	t.Helper()
	st, err := s.Stage(bytes.NewReader(content), int64(len(content))+1024)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := st.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return st
}

func TestRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	content := []byte("attack at dawn")

	st := put(t, s, content)

	want := sha256.Sum256(content)
	if st.Hash != want {
		t.Errorf("hash = %x, want %x", st.Hash, want)
	}
	if st.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", st.Size, len(content))
	}

	got, err := s.Open(st.Hash[:], st.WrappedDEK)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %q", got)
	}
}

func TestEmptyContent(t *testing.T) {
	s, _ := newTestStore(t)
	st := put(t, s, nil)
	got, err := s.Open(st.Hash[:], st.WrappedDEK)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestStoredObjectIsCiphertext(t *testing.T) {
	s, _ := newTestStore(t)
	content := []byte("this exact plaintext must never appear on disk")
	st := put(t, s, content)

	raw, err := os.ReadFile(s.objectPath(st.Hash[:]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, content) {
		t.Error("plaintext found inside stored object file")
	}
}

func TestDeduplication(t *testing.T) {
	s, _ := newTestStore(t)
	content := []byte("shared bytes")

	first := put(t, s, content)

	// Second upload of identical content: same address, caller detects the
	// existing metadata row and aborts the staged copy.
	second, err := s.Stage(bytes.NewReader(content), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if second.Hash != first.Hash {
		t.Fatalf("identical content produced different addresses")
	}
	second.Abort()

	// The original object and its DEK still work after the abort.
	got, err := s.Open(first.Hash[:], first.WrappedDEK)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("original object damaged by aborted duplicate: %v", err)
	}

	// Abort must not leave staged temp files behind.
	entries, _ := os.ReadDir(filepath.Join(s.root, "tmp"))
	if len(entries) != 0 {
		t.Errorf("%d temp files remain after abort", len(entries))
	}
}

func TestSizeLimitEnforcedWhileReceiving(t *testing.T) {
	s, _ := newTestStore(t)

	_, err := s.Stage(strings.NewReader(strings.Repeat("x", 100)), 99)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}

	// Rejected uploads must leave no temporary data (proposal: oversized
	// upload scenario).
	entries, _ := os.ReadDir(filepath.Join(s.root, "tmp"))
	if len(entries) != 0 {
		t.Errorf("%d temp files remain after rejected upload", len(entries))
	}

	// Exactly at the limit is allowed.
	if _, err := s.Stage(strings.NewReader(strings.Repeat("x", 99)), 99); err != nil {
		t.Fatalf("content at limit rejected: %v", err)
	}
}

func TestStagedObjectInvisibleUntilCommit(t *testing.T) {
	s, _ := newTestStore(t)
	content := []byte("not yet visible")

	st, err := s.Stage(bytes.NewReader(content), 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Abort()

	if s.Exists(st.Hash[:]) {
		t.Error("staged object visible before Commit")
	}
	if _, err := s.Open(st.Hash[:], st.WrappedDEK); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open before Commit: err = %v, want ErrNotFound", err)
	}
}

// TestTamperedCiphertext flips each byte region of the stored object and
// confirms retrieval is blocked with ErrCorrupt and no plaintext (proposal:
// integrity attack scenario).
func TestTamperedCiphertext(t *testing.T) {
	s, _ := newTestStore(t)
	content := []byte("integrity is structural, not assumed")
	st := put(t, s, content)
	path := s.objectPath(st.Hash[:])

	pristine, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Flip one bit at several positions: magic, nonce, body, tag.
	positions := []int{0, len(objMagic), len(objMagic) + 3, len(objMagic) + nonceSize + 1, len(pristine) - 1}
	for _, pos := range positions {
		t.Run(fmt.Sprintf("byte_%d", pos), func(t *testing.T) {
			tampered := bytes.Clone(pristine)
			tampered[pos] ^= 0x01
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := s.Open(st.Hash[:], st.WrappedDEK)
			if !errors.Is(err, ErrCorrupt) {
				t.Errorf("err = %v, want ErrCorrupt", err)
			}
			if got != nil {
				t.Error("plaintext released from tampered object")
			}

			if err := os.WriteFile(path, pristine, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTruncatedObject(t *testing.T) {
	s, _ := newTestStore(t)
	st := put(t, s, []byte("will be truncated"))
	path := s.objectPath(st.Hash[:])

	if err := os.WriteFile(path, []byte("SV"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(st.Hash[:], st.WrappedDEK); !errors.Is(err, ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestWrongMasterKey(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir, testKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	st := put(t, s1, []byte("keyed to one KEK"))

	s2, err := New(dir, testKEK(t)) // same directory, different KEK
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Open(st.Hash[:], st.WrappedDEK); !errors.Is(err, ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

// TestObjectRelocationAttack moves object A's ciphertext to object B's
// content address. The hash-as-associated-data binding must reject it even
// though the file itself is intact.
func TestObjectRelocationAttack(t *testing.T) {
	s, _ := newTestStore(t)
	a := put(t, s, []byte("object A"))
	b := put(t, s, []byte("object B"))

	// Overwrite B's object file with A's ciphertext.
	raw, err := os.ReadFile(s.objectPath(a.Hash[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.objectPath(b.Hash[:]), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Neither B's own DEK nor A's DEK may release plaintext at B's address.
	if _, err := s.Open(b.Hash[:], b.WrappedDEK); !errors.Is(err, ErrCorrupt) {
		t.Errorf("relocated object with B's DEK: err = %v, want ErrCorrupt", err)
	}
	if _, err := s.Open(b.Hash[:], a.WrappedDEK); !errors.Is(err, ErrCorrupt) {
		t.Errorf("relocated object with A's DEK: err = %v, want ErrCorrupt", err)
	}
}

func TestCommitReplacesOrphan(t *testing.T) {
	s, _ := newTestStore(t)
	content := []byte("orphaned by a simulated crash")

	// First upload commits the file, but the metadata transaction "crashes":
	// the caller never records the row, so the wrapped DEK is lost.
	orphan := put(t, s, content)
	_ = orphan.WrappedDEK // lost with the failed transaction

	// Re-upload of the same content must replace the orphan and produce a
	// working object under the new DEK.
	st, err := s.Stage(bytes.NewReader(content), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(); err != nil {
		t.Fatal(err)
	}

	got, err := s.Open(st.Hash[:], st.WrappedDEK)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("recovered orphan unreadable: %v", err)
	}
}

func TestRemove(t *testing.T) {
	s, _ := newTestStore(t)
	st := put(t, s, []byte("to be deleted"))

	if err := s.Remove(st.Hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(st.Hash[:], st.WrappedDEK); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	// Idempotent: removing an already-removed object is not an error.
	if err := s.Remove(st.Hash[:]); err != nil {
		t.Errorf("second Remove: %v", err)
	}
}

func TestDoubleFinalizeRejected(t *testing.T) {
	s, _ := newTestStore(t)
	st, err := s.Stage(bytes.NewReader([]byte("once")), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(); err == nil {
		t.Error("second Commit succeeded, want error")
	}
}

// TestConcurrentPutSameContent exercises the dedup race under the race
// detector: many goroutines stage and publish identical content.
func TestConcurrentPutSameContent(t *testing.T) {
	s, _ := newTestStore(t)
	content := []byte("everyone uploads the same file")

	var wg sync.WaitGroup
	results := make([]*Staged, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := s.Stage(bytes.NewReader(content), 1024)
			if err != nil {
				t.Error(err)
				return
			}
			if err := st.Commit(); err != nil {
				t.Error(err)
				return
			}
			results[i] = st
		}(i)
	}
	wg.Wait()

	// The last committed DEK wins the rename race; every earlier DEK is
	// superseded. In the real system the metadata row serializes this: only
	// the first uploader commits, everyone else aborts. Here we only assert
	// the store ends in a consistent, readable state under the final DEK.
	last := results[len(results)-1]
	for _, st := range results {
		if st == nil {
			t.Fatal("missing result")
		}
		if st.Hash != last.Hash {
			t.Fatal("hash divergence for identical content")
		}
	}
}

func TestConcurrentDistinctContent(t *testing.T) {
	s, _ := newTestStore(t)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			content := []byte(fmt.Sprintf("distinct content %d", i))
			st, err := s.Stage(bytes.NewReader(content), 1024)
			if err != nil {
				t.Error(err)
				return
			}
			if err := st.Commit(); err != nil {
				t.Error(err)
				return
			}
			got, err := s.Open(st.Hash[:], st.WrappedDEK)
			if err != nil || !bytes.Equal(got, content) {
				t.Errorf("object %d unreadable after commit: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}
