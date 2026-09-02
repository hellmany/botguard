package bgfiber

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
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

func TestRegisterAndShim(t *testing.T) {
	g := newGuard(t, false)
	app := fiber.New()
	Register(g, app)
	var seen bool
	var ref string
	app.Get("/u/x", func(c *fiber.Ctx) error {
		_, seen = VerdictFrom(c)
		ref = c.Get("Referer")
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.SendString(`<html><head><title>t</title></head><body>hi</body></html>`)
	})
	req := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	req.Header.Set("Referer", "https://example.com/u/x")
	req.AddCookie(&http.Cookie{Name: "bg_ref", Value: url.QueryEscape("https://yandex.ru/")})
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("X-BG-Decision") == "" {
		t.Fatalf("status %d, decision header %q", resp.StatusCode, resp.Header.Get("X-BG-Decision"))
	}
	if !strings.Contains(string(body), `return "https://yandex.ru/"`) {
		t.Errorf("shim missing:\n%s", body)
	}
	if !seen || ref != "https://yandex.ru/" {
		t.Errorf("verdict seen=%v, handler saw Referer=%q", seen, ref)
	}
}

func TestDisabledRegistersNothing(t *testing.T) {
	app := fiber.New()
	Register(newGuard(t, true), app)
	if n := len(app.GetRoutes(true)); n != 0 {
		t.Errorf("%d routes registered in ModeOff", n)
	}
}
