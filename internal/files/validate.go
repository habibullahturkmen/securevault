package files

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"unicode"
)

// ErrValidation wraps every upload-policy rejection so the API layer can
// map it to a 400 without leaking internals.
var ErrValidation = errors.New("validation failed")

const maxFilenameLen = 255

// SanitizeFilename reduces a client-supplied filename to safe display
// metadata. The result is NEVER used to build a filesystem path — storage
// names come exclusively from content hashes — so sanitization here is
// about neutralizing traversal sequences, control characters, and absurd
// lengths before the name is stored and echoed back (escaped) by the UI.
func SanitizeFilename(name string) string {
	// Keep only the final path element of whatever the client sent.
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	// Drop control characters and other non-printables.
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	// Names that are only dots are path navigation, not names.
	if strings.Trim(name, ".") == "" {
		name = ""
	}
	if name == "" {
		return "unnamed"
	}
	if len(name) > maxFilenameLen {
		name = name[:maxFilenameLen]
	}
	return name
}

// zipContainerTypes are declared types whose on-disk signature is a ZIP
// archive; DetectContentType reports them all as application/zip.
var zipContainerTypes = map[string]bool{
	"application/zip":          true,
	"application/java-archive": true,
	"application/epub+zip":     true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
}

// sniffablePrefixes are content families http.DetectContentType can
// recognize from magic bytes. If content is declared as one of these but
// sniffing sees random bytes, the declaration is a lie.
var sniffablePrefixes = []string{"image/", "video/", "audio/", "text/"}

var sniffableExact = map[string]bool{
	"application/pdf":  true,
	"application/zip":  true,
	"application/gzip": true,
}

// ValidateContent checks the declared MIME type against the magic-byte
// signature of the first bytes of content (proposal: "MIME and magic-byte
// file signature validation; any mismatch rejects the upload"). It returns
// the normalized type to store.
func ValidateContent(declared string, head []byte) (string, error) {
	declaredType, _, err := mime.ParseMediaType(declared)
	if err != nil || declaredType == "" {
		return "", fmt.Errorf("%w: malformed content type %q", ErrValidation, declared)
	}
	declaredType = strings.ToLower(declaredType)

	detected, _, err := mime.ParseMediaType(http.DetectContentType(head))
	if err != nil {
		return "", fmt.Errorf("%w: undetectable content", ErrValidation)
	}

	switch {
	case detected == declaredType:
		return declaredType, nil
	case detected == "application/zip" && zipContainerTypes[declaredType]:
		// ZIP-based document formats legitimately sniff as zip.
		return declaredType, nil
	case detected == "text/plain" && strings.HasPrefix(declaredType, "text/"):
		// Sniffing cannot tell text subtypes (csv, markdown, …) apart.
		return declaredType, nil
	case detected == "application/octet-stream":
		// Content the sniffer cannot identify: only credible for declared
		// types that are not themselves sniffable.
		if sniffableExact[declaredType] {
			return "", mismatch(declaredType, detected)
		}
		for _, p := range sniffablePrefixes {
			if strings.HasPrefix(declaredType, p) {
				return "", mismatch(declaredType, detected)
			}
		}
		return declaredType, nil
	default:
		return "", mismatch(declaredType, detected)
	}
}

func mismatch(declared, detected string) error {
	return fmt.Errorf("%w: declared type %q does not match detected signature %q",
		ErrValidation, declared, detected)
}
