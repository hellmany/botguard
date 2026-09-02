package bggin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hellmany/botguard"
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
	gin.SetMode(gin.TestMode)
	g := newGuard(t, false)
	r := gin.New()
	Register(g, r)
	var seen bool
	r.GET("/u/x", func(c *gin.Context) {
		_, seen = VerdictFrom(c)
		c.String(200, "ok")
	})
	if len(r.Routes()) < len(g.Routes()) {
		t.Fatalf("routes: %d registered, guard needs %d", len(r.Routes()), len(g.Routes()))
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/u/x", nil))
	if w.Code != 200 || !seen || w.Header().Get("X-BG-Decision") == "" {
		t.Fatalf("status %d, verdict seen=%v", w.Code, seen)
	}
}

func TestShimReachesGinResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	g := newGuard(t, false)
	r := gin.New()
	Register(g, r)
	r.GET("/u/x", func(c *gin.Context) {
		c.Data(200, "text/html; charset=utf-8", []byte(`<html><head><title>t</title></head><body>hi</body></html>`))
	})
	req := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	req.Header.Set("Referer", "https://example.com/u/x")
	req.AddCookie(&http.Cookie{Name: "bg_ref", Value: url.QueryEscape("https://yandex.ru/")})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `return "https://yandex.ru/"`) {
		t.Errorf("shim missing:\n%s", w.Body.String())
	}
}

func TestDisabledRegistersNothing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(newGuard(t, true), r)
	if n := len(r.Routes()); n != 0 {
		t.Errorf("%d routes registered in ModeOff", n)
	}
}
