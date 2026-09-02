package bgecho

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hellmany/botguard"
	"github.com/labstack/echo/v4"
)

func newGuard(t *testing.T, disabled bool) *botguard.Guard {
	t.Helper()
	p := botguard.DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Enforce = true
	p.Disabled = disabled
	g, err := botguard.New(nil, botguard.NewConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRegisterInstallsRoutesAndVerdict(t *testing.T) {
	g := newGuard(t, false)
	e := echo.New()
	Register(g, e)
	var got botguard.Verdict
	var seen bool
	e.GET("/u/x", func(c echo.Context) error {
		got, seen = VerdictFrom(c)
		return c.String(200, "ok")
	})
	if len(e.Routes()) < len(g.Routes()) {
		t.Fatalf("routes: %d registered, guard needs %d", len(e.Routes()), len(g.Routes()))
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/u/x", nil))
	if w.Code != 200 || !seen {
		t.Fatalf("status %d, verdict seen=%v", w.Code, seen)
	}
	if got.Decision.String() == "" || w.Header().Get("X-BG-Decision") == "" {
		t.Error("verdict not propagated")
	}
}

// Echo's writes go through the wrapped writer the core hands back.
func TestShimReachesEchoResponse(t *testing.T) {
	g := newGuard(t, false)
	e := echo.New()
	Register(g, e)
	e.GET("/u/x", func(c echo.Context) error {
		return c.HTML(200, `<html><head><title>t</title></head><body>hi</body></html>`)
	})
	r := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r.Header.Set("Referer", "https://example.com/u/x")
	r.AddCookie(&http.Cookie{Name: "bg_ref", Value: url.QueryEscape("https://yandex.ru/")})
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `return "https://yandex.ru/"`) {
		t.Errorf("shim missing:\n%s", w.Body.String())
	}
}

func TestDisabledRegistersNothing(t *testing.T) {
	e := echo.New()
	Register(newGuard(t, true), e)
	if n := len(e.Routes()); n != 0 {
		t.Errorf("%d routes registered in ModeOff", n)
	}
}
