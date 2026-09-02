package botguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// End-to-end through the real Middleware: challenge -> reload -> application.
// The app must see the original traffic source, not our challenge page.
func TestMiddlewareRestoresRefererE2E(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	g, err := New(nil, NewConfig(p))
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	var seenByApp string
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		seenByApp = r.Referer()
		_, _ = w.Write([]byte("ok"))
	})
	h := g.HTTPMiddleware(mux)

	// Step 1: serving the challenge stashes the original referrer.
	r1 := httptest.NewRequest("GET", "http://example.com/target", nil)
	r1.Header.Set("Referer", "https://yandex.com/")
	w1 := httptest.NewRecorder()
	g.saveOrigReferer(w1, r1, false)
	cookies := w1.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("challenge did not stash the referrer")
	}

	// Step 2: on reload the browser substitutes the page itself.
	r2 := httptest.NewRequest("GET", "http://example.com/target", nil)
	r2.Header.Set("Referer", "https://example.com/target")
	for _, c := range cookies {
		r2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)

	if seenByApp != "https://yandex.com/" {
		t.Fatalf("app saw Referer=%q, want the original source", seenByApp)
	}
	if !strings.Contains(w2.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("cookie must be cleared after use: %q", w2.Header().Get("Set-Cookie"))
	}
}
