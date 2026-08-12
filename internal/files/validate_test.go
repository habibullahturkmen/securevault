package files

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	cases := []struct{ in, want string }{
		{"report.pdf", "report.pdf"},
		{"../../etc/passwd", "passwd"},
		{`..\..\boot.ini`, "boot.ini"},
		{"/absolute/path/name.txt", "name.txt"},
		{"..", "unnamed"},
		{"...", "unnamed"},
		{"", "unnamed"},
		{"   ", "unnamed"},
		{"nul\x00byte.txt", "nulbyte.txt"},
		{"line\nbreak.txt", "linebreak.txt"},
		{"<script>.txt", "<script>.txt"}, // neutralized by output encoding, not here
		{strings.Repeat("a", 300), strings.Repeat("a", 255)},
	}
	for _, c := range cases {
		if got := SanitizeFilename(c.in); got != c.want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateContent(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	pdf := []byte("%PDF-1.7 ...")
	binary := []byte{0x00, 0x01, 0x02, 0x03}

	accept := []struct {
		declared string
		head     []byte
	}{
		{"image/png", png},
		{"application/pdf", pdf},
		{"text/plain", []byte("hello world")},
		{"text/csv", []byte("a,b,c")},                  // text subtypes sniff as text/plain
		{"text/plain; charset=utf-8", []byte("hello")}, // parameters are normalized away
		{"application/octet-stream", binary},           // unsniffable + generic declaration
		{"application/x-custom", binary},               // unsniffable + non-sniffable type
	}
	for _, c := range accept {
		if _, err := ValidateContent(c.declared, c.head); err != nil {
			t.Errorf("ValidateContent(%q) rejected valid content: %v", c.declared, err)
		}
	}

	reject := []struct {
		declared string
		head     []byte
	}{
		{"text/plain", png},         // PNG masquerading as text
		{"image/png", binary},       // random bytes claiming to be an image
		{"image/png", pdf},          // PDF claiming to be an image
		{"application/pdf", binary}, // unsniffable claiming a sniffable type
		{"", []byte("x")},           // missing declaration
		{"not a mime type at all;;;", []byte("x")},
	}
	for _, c := range reject {
		if _, err := ValidateContent(c.declared, c.head); !errors.Is(err, ErrValidation) {
			t.Errorf("ValidateContent(%q) = %v, want ErrValidation", c.declared, err)
		}
	}
}
