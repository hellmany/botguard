package botguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Without JA4 (missing header or "-", as behind Cloudflare) the fingerprint
// comes from the HTTP headers.
func TestWorksWithoutJA4(t *testing.T) {
	g := &Guard{cfg: DefaultConfig([]byte("0123456789abcdef0123456789abcdef"))}
	g.cfg.Headers = DefaultHeaderConfig()
	g.trustedASN = map[uint32]bool{}

	mk := func(ja4, ua string) Signals {
		r := httptest.NewRequest(http.MethodGet, "https://example.com/page", nil)
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if ja4 != "" {
			r.Header.Set("X-JA4", ja4)
		}
		return g.extract(r)
	}

	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
	firefox := "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

	t.Run("with JA4", func(t *testing.T) {
		s := mk("t13d1516h2_8daaf6152771_0adf69b4533f", chrome)
		if s.FPKind != "ja4" || s.FPrint != "t13d1516h2_8daaf6152771_0adf69b4533f" {
			t.Errorf("want ja4, got kind=%q fp=%q", s.FPKind, s.FPrint)
		}
	})

	t.Run("without JA4 — fallback", func(t *testing.T) {
		s := mk("", chrome)
		if s.FPKind != "http" {
			t.Errorf("want the http fallback, got %q", s.FPKind)
		}
		if s.FPrint == "" {
			t.Error("empty fingerprint: the fingerprint dimensions go dark")
		}
	})

	t.Run("JA4 is a dash (Cloudflare)", func(t *testing.T) {
		s := mk("-", chrome)
		if s.FPKind != "http" {
			t.Errorf("a dash should fall back, got %q", s.FPKind)
		}
		if s.JA4 != "" {
			t.Errorf(`JA4 must be cleared so "-" never reaches the stats, got %q`, s.JA4)
		}
	})

	t.Run("different browsers give different fingerprints", func(t *testing.T) {
		a := mk("", chrome)
		b := mk("", firefox)
		if a.FPrint == b.FPrint {
			t.Error("Chrome and Firefox got the SAME fingerprint — all traffic collapses into one key")
		}
	})

	t.Run("one browser gives a stable fingerprint", func(t *testing.T) {
		if mk("", chrome).FPrint != mk("", chrome).FPrint {
			t.Error("unstable fingerprint: counters will never accumulate")
		}
	})
}

// NeedFingerprint dimensions work on the http fallback too.
func TestDimensionsWorkWithoutJA4(t *testing.T) {
	g := &Guard{cfg: DefaultConfig([]byte("0123456789abcdef0123456789abcdef"))}
	g.cfg.Headers = DefaultHeaderConfig()
	g.trustedASN = map[uint32]bool{}
	g.cfg.Dimensions = dimensionsB()

	r := httptest.NewRequest(http.MethodGet, "https://example.com/x", nil)
	r.Header.Set("X-Real-IP", "203.0.113.7")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0")
	r.Header.Set("Accept", "text/html")
	// no X-JA4
	s := g.extract(r)

	var withFP int
	for _, d := range g.activeDimensions(s) {
		if d.NeedFingerprint {
			withFP++
			if d.Key(s) == "" {
				t.Errorf("dimension %q produced an empty key without JA4", d.Name)
			}
		}
	}
	if withFP == 0 {
		t.Error("no fingerprint dimension is active: botnet protection is off without JA4")
	}
}
