package api

// Audit-log paging: newest first, keyset on id, no gaps or overlaps across
// pages, parameter validation.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestAuditPagination(t *testing.T) {
	e := newEnv(t)
	adminName := uniqueUser("auditor")
	admin := e.registerAndLogin(adminName)
	e.promoteToAdmin(adminName)
	// Each registration + login writes events; make sure there are > 2 pages.
	for i := 0; i < 6; i++ {
		e.registerAndLogin(uniqueUser("filler"))
	}

	type page struct {
		Events []struct {
			ID int64 `json:"id"`
		} `json:"events"`
		NextBefore *int64 `json:"nextBefore"`
	}
	fetch := func(query string) page {
		var p page
		json.Unmarshal(admin.req("GET", "/api/admin/audit"+query, nil, "", http.StatusOK), &p)
		return p
	}

	seen := map[int64]bool{}
	var lastID int64
	pages := 0
	var cursor *int64
	for {
		q := "?limit=5"
		if cursor != nil {
			q += fmt.Sprintf("&before=%d", *cursor)
		}
		p := fetch(q)
		pages++
		if len(p.Events) == 0 || len(p.Events) > 5 {
			t.Fatalf("page %d has %d events, want 1-5", pages, len(p.Events))
		}
		for _, ev := range p.Events {
			if seen[ev.ID] {
				t.Fatalf("event %d returned twice (pages overlap)", ev.ID)
			}
			if lastID != 0 && ev.ID >= lastID {
				t.Fatalf("event %d after %d: not strictly newest-first", ev.ID, lastID)
			}
			seen[ev.ID] = true
			lastID = ev.ID
		}
		if p.NextBefore == nil {
			break
		}
		if *p.NextBefore != lastID {
			t.Errorf("nextBefore = %d, want last id on page %d", *p.NextBefore, lastID)
		}
		cursor = p.NextBefore
		if pages > 100 {
			t.Fatal("paging never terminates")
		}
	}
	if pages < 3 {
		t.Errorf("walked %d pages, want at least 3", pages)
	}

	// Everything in one go must equal the union of the pages.
	all := fetch("?limit=1000")
	if len(all.Events) != len(seen) || all.NextBefore != nil {
		t.Errorf("single page = %d events (nextBefore %v), paged walk saw %d", len(all.Events), all.NextBefore, len(seen))
	}

	// Validation.
	for _, bad := range []string{"?limit=0", "?limit=1001", "?limit=x", "?before=0", "?before=-3", "?before=abc"} {
		if code := admin.statusOf("GET", "/api/admin/audit"+bad, nil, ""); code != http.StatusBadRequest {
			t.Errorf("GET /api/admin/audit%s = %d, want 400", bad, code)
		}
	}
}
