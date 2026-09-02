package botguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func trkGuard(t *testing.T, name string) (*Guard, http.Handler) {
	t.Helper()
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Enforce = true
	p.TrackingCookie = name
	g, err := New(nil, NewConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	g.RegisterMux(mux)
	mux.HandleFunc("/u/x", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	return g, g.HTTPMiddleware(mux)
}

// Off by default: no name, no cookie.
func TestTrackingCookieDefaultOff(t *testing.T) {
	_, e := trkGuard(t, "")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/u/x", nil))
	if sc := w.Header().Get("Set-Cookie"); strings.Contains(sc, "bg_trk") {
		t.Errorf("cookie set with no name configured: %q", sc)
	}
}

// The first response tags the browser, a challenge included.
func TestTrackingCookieSetOnFirstResponse(t *testing.T) {
	_, e := trkGuard(t, "bg_trk")
	r := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	found := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == "bg_trk" {
			found = c.Value
		}
	}
	if found == "" {
		t.Fatal("the first response must carry the tracking cookie")
	}
	if len(found) < 12 {
		t.Errorf("id too short: %q", found)
	}
}

// An already-tagged browser keeps its id.
func TestTrackingCookieNotChurned(t *testing.T) {
	_, e := trkGuard(t, "bg_trk")
	r := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r.AddCookie(&http.Cookie{Name: "bg_trk", Value: "existing-id"})
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == "bg_trk" {
			t.Errorf("the id was reissued: %q", c.Value)
		}
	}
}

// The first response carries the id in the header too; the request cookie
// is empty on first contact.
func TestTrackingHeaderOnFirstResponse(t *testing.T) {
	_, e := trkGuard(t, "bg_trk")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/u/x", nil))
	hdr := w.Header().Get(TrackingHeader)
	if hdr == "" {
		t.Fatal("no tracking header on the first response")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "bg_trk" && c.Value != hdr {
			t.Errorf("header %q differs from the issued cookie %q", hdr, c.Value)
		}
	}
}

// A returning browser gets its own id echoed back.
func TestTrackingHeaderEchoesExistingID(t *testing.T) {
	_, e := trkGuard(t, "bg_trk")
	r := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r.AddCookie(&http.Cookie{Name: "bg_trk", Value: "existing-id"})
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if got := w.Header().Get(TrackingHeader); got != "existing-id" {
		t.Errorf("header = %q, want the browser's own id", got)
	}
}
