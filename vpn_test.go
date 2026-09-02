package botguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A visitor behind a shared exit (VPN, Tor) keeps the pass even though a
// neighbour's traffic keeps the score high.
func TestClearedVisitorKeepsPassBehindSharedExit(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Enforce = true
	g, err := New(nil, NewConfig(p))
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/u/x", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	e := g.HTTPMiddleware(mux)

	// Issue a pass the way a solved challenge does.
	r0 := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	w0 := httptest.NewRecorder()
	g.issueClearance(w0, g.extract(r0), false)
	pass := w0.Result().Cookies()
	if len(pass) == 0 {
		t.Fatal("no clearance issued")
	}

	// Come back through the same shared exit.
	r := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r.Header.Set("X-Usertype", "hosting") // VPN/Tor exit
	for _, c := range pass {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)

	if sc := w.Header().Get("Set-Cookie"); strings.Contains(sc, "bg_clearance=;") ||
		strings.Contains(sc, "Max-Age=0") {
		t.Errorf("the pass was wiped, visitor will loop: %q", sc)
	}
	if w.Code == 503 {
		t.Errorf("a cleared visitor was challenged again (status %d)", w.Code)
	}
}
