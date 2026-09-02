package botguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testGuard(t *testing.T) *Guard {
	t.Helper()
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	g, err := New(nil, NewConfig(p))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// The Secure flag follows the scheme; a Secure cookie on plain HTTP is
// dropped by the browser.
func TestSaveOrigRefererSecureFlag(t *testing.T) {
	g := testGuard(t)
	for _, secure := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/target", nil)
		r.Header.Set("Referer", "https://yandex.com/")
		w := httptest.NewRecorder()
		g.saveOrigReferer(w, r, secure)
		sc := w.Header().Get("Set-Cookie")
		if !strings.Contains(sc, origRefCookie+"=") {
			t.Fatalf("secure=%v: no cookie set: %q", secure, sc)
		}
		if has := strings.Contains(sc, "Secure"); has != secure {
			t.Errorf("secure=%v: Secure flag present=%v, cookie=%q", secure, has, sc)
		}
	}
}

func TestIsSecureReq(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if isSecureReq(r, "http") {
		t.Error("plain http must not be secure")
	}
	if !isSecureReq(r, "https") {
		t.Error("proxied https must be secure")
	}
}

// Round trip: the source is stashed at the challenge and handed back once.
func TestRefererRoundTrip(t *testing.T) {
	g := testGuard(t)

	r1 := httptest.NewRequest("GET", "/target", nil)
	r1.Header.Set("Referer", "https://yandex.com/")
	w1 := httptest.NewRecorder()
	g.saveOrigReferer(w1, r1, false)

	// The reload arrives with the challenge page as its referrer.
	r2 := httptest.NewRequest("GET", "/target", nil)
	r2.Header.Set("Referer", "https://example.com/target")
	for _, c := range w1.Result().Cookies() {
		r2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	g.restoreOrigReferer(w2, r2, false)

	if got := r2.Referer(); got != "https://yandex.com/" {
		t.Fatalf("Referer after restore = %q, want the original source", got)
	}
	if !strings.Contains(w2.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("cookie must be cleared after use, got %q", w2.Header().Get("Set-Cookie"))
	}
}

// The cookie is visitor-controlled, so junk must not reach analytics.
func TestRestoreRejectsHostileValues(t *testing.T) {
	g := testGuard(t)
	bad := []string{
		"javascript:alert(1)",
		"/relative/path",
		"not a url",
		"data:text/html,<script>",
	}
	for _, v := range bad {
		r := httptest.NewRequest("GET", "/x", nil)
		r.Header.Set("Referer", "https://example.com/x")
		r.AddCookie(&http.Cookie{Name: origRefCookie, Value: v})
		g.restoreOrigReferer(httptest.NewRecorder(), r, false)
		if got := r.Referer(); got != "https://example.com/x" {
			t.Errorf("hostile value %q leaked into Referer: %q", v, got)
		}
	}
}

// The stash survives the challenge rounds: only the first request carries
// the real source, later ones carry our own page.
func TestChallengeDoesNotOverwriteStash(t *testing.T) {
	g := testGuard(t)

	// Arriving from a search engine, challenged.
	r1 := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r1.Header.Set("Referer", "https://yandex.ru/")
	w1 := httptest.NewRecorder()
	g.saveOrigReferer(w1, r1, false)
	cookies := w1.Result().Cookies()

	// The reload carries our own page as the referrer. The stash must not be
	// touched: this visitor has not passed yet.
	r2 := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r2.Header.Set("Referer", "https://example.com/u/x")
	for _, c := range cookies {
		r2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	g.saveOrigReferer(w2, r2, false)

	for _, c := range w2.Result().Cookies() {
		if c.Name == origRefCookie && c.Value != "" {
			t.Fatalf("the stash was overwritten with our own page: %q", c.Value)
		}
	}

	// Once through, the original source is handed back.
	r3 := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r3.Header.Set("Referer", "https://example.com/u/x")
	for _, c := range cookies {
		r3.AddCookie(c)
	}
	g.restoreOrigReferer(httptest.NewRecorder(), r3, false)
	if got := r3.Referer(); got != "https://yandex.ru/" {
		t.Errorf("Referer = %q, want the original source", got)
	}
}

// A direct visit comes out of the challenge as a direct visit, not as a
// self-referral.
func TestDirectVisitStaysDirect(t *testing.T) {
	g := testGuard(t)

	r1 := httptest.NewRequest("GET", "http://example.com/u/x", nil) // no referrer
	w1 := httptest.NewRecorder()
	g.saveOrigReferer(w1, r1, false)
	cookies := w1.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Value != origRefEmpty {
		t.Fatalf("an empty referrer must be stashed with the marker, got %+v", cookies)
	}

	r2 := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r2.Header.Set("Referer", "https://example.com/u/x") // reload artifact
	for _, c := range cookies {
		r2.AddCookie(c)
	}
	ref, ok := g.restoreOrigReferer(httptest.NewRecorder(), r2, false)
	if !ok || ref != "" {
		t.Fatalf("restore = (%q, %v), want an empty restored referrer", ref, ok)
	}
	if got := r2.Referer(); got != "" {
		t.Errorf("the app still sees a self-referral: %q", got)
	}
}

// An internal referrer is part of the visitor's real path and comes back too.
func TestInternalRefererPreserved(t *testing.T) {
	g := testGuard(t)

	r1 := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r1.Header.Set("Referer", "https://example.com/section")
	w1 := httptest.NewRecorder()
	g.saveOrigReferer(w1, r1, false)

	r2 := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r2.Header.Set("Referer", "https://example.com/u/x")
	for _, c := range w1.Result().Cookies() {
		r2.AddCookie(c)
	}
	if ref, ok := g.restoreOrigReferer(httptest.NewRecorder(), r2, false); !ok || ref != "https://example.com/section" {
		t.Fatalf("restore = (%q, %v)", ref, ok)
	}
	if r2.Referer() != "https://example.com/section" {
		t.Errorf("app sees %q", r2.Referer())
	}
}
