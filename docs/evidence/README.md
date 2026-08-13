# Evidence bundle

Captured artifacts for the report's Testing & Validation section. Each file
names the commit it was produced against.

| File | What it is |
|---|---|
| `test-run.txt` | Full verbose `go test -race` run: 49 tests, 0 failures — storage tamper/relocation attacks, adversarial auth suite, authorization matrix, HTTP integration |
| `tamper-demo.txt` | Live integrity-attack transcript: upload → verified download → one ciphertext byte flipped on disk → download blocked with controlled 500 → `integrity_failure` row in the audit log |
| `zap-report.html` | OWASP ZAP baseline scan report (open in a browser; attach to the report) |
| `zap-summary.txt` | ZAP result summary: **FAIL: 0 · WARN: 2 · PASS: 65** |
| `zap.yaml` | The automation plan ZAP generated for the scan (documents scan config) |

## ZAP warning justifications (required by proposal §7: resolved or justified)

Both remaining warnings are informational and deliberate:

1. **Non-Storable Content [10049]** — the app sends `Cache-Control: no-store`
   on pages and downloads. For a system serving confidential files this is
   the *desired* behavior (no copies in shared caches or browser disk
   cache); ZAP flags it only because it prevents caching. Not a defect.
2. **Modern Web Application [10109]** — informational fingerprint that the
   target is a JavaScript SPA. Not a finding.

Two earlier warnings (`Permissions-Policy` missing, `Cross-Origin-Embedder-
Policy` missing) were **fixed** in response to the first scan — the headers
are now set in `internal/api/middleware.go` and asserted by
`TestSecurityHeadersPresent`. This scan-fix-rescan cycle is itself evidence
of the pipeline working as designed.

## Scan scope note

The local scan targets the app binary directly over HTTP — identical scope
to the CI `zap-baseline` job. ZAP's Java TLS client cannot complete a
handshake with Caddy's locally-issued demo certificate (`tls internal`);
the TLS layer is stock Caddy 2 and its transport headers (HSTS) are
evidenced separately in the compose smoke checks. A scan through a real
certificate becomes possible once the stack runs under a real domain.

## Still to capture (needs the team's accounts)

- [ ] Push to GitHub → CI history on every commit (proposal deliverable 1)
- [ ] Actions → `ci` → *Run workflow* → attach the CI-hosted ZAP artifact
- [ ] Browser screenshots for the slides: login, file list, sharing dialog,
      admin audit view (the denied rows render highlighted)
