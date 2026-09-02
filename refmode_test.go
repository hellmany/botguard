package botguard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func guardWithMode(t *testing.T, mode string) *Guard {
	t.Helper()
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Enforce = true
	p.RefererMode = mode
	g, err := New(nil, NewConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func serveWithStash(t *testing.T, g *Guard, target string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/u/x", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><head><title>t</title></head><body>hi</body></html>`))
	})
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("Referer", "https://example.com/u/x")
	r.AddCookie(&http.Cookie{Name: origRefCookie, Value: url.QueryEscape("https://yandex.ru/")})
	w := httptest.NewRecorder()
	g.HTTPMiddleware(mux).ServeHTTP(w, r)
	return w
}

// Mode "off": the header is restored, the HTML is untouched.
func TestRefererModeOff(t *testing.T) {
	w := serveWithStash(t, guardWithMode(t, "off"), "http://example.com/u/x")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "<script>") {
		t.Errorf("mode off must not inject: %s", w.Body.String())
	}
}

// Mode "inject" (and the empty default): the shim follows <head>.
func TestRefererModeInject(t *testing.T) {
	for _, mode := range []string{"inject", ""} {
		w := serveWithStash(t, guardWithMode(t, mode), "http://example.com/u/x")
		if w.Code != 200 {
			t.Fatalf("mode %q: status %d", mode, w.Code)
		}
		if !strings.Contains(w.Body.String(), `return "https://yandex.ru/"`) {
			t.Errorf("mode %q: shim missing:\n%s", mode, w.Body.String())
		}
	}
}

// Mode "param": one redirect adds the source to the URL, the next request
// passes through with the header restored and no second redirect.
func TestRefererModeParam(t *testing.T) {
	g := guardWithMode(t, "param")

	w := serveWithStash(t, g, "http://example.com/u/x")
	if w.Code != http.StatusFound {
		t.Fatalf("want a redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil || u.Query().Get("bg_ref") != "https://yandex.ru/" {
		t.Fatalf("bad redirect target: %q", loc)
	}

	// Follow the redirect: parameter present, no loop, header restored.
	w2 := serveWithStash(t, g, loc)
	if w2.Code != 200 {
		t.Fatalf("after redirect: status %d, loc=%q", w2.Code, loc)
	}
	if strings.Contains(w2.Body.String(), "<script>") {
		t.Errorf("param mode must not inject")
	}
}

// A direct visit has nothing to put in the URL: no redirect in param mode.
func TestRefererModeParamDirectVisit(t *testing.T) {
	g := guardWithMode(t, "param")
	mux := http.NewServeMux()
	mux.HandleFunc("/u/x", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	r := httptest.NewRequest("GET", "http://example.com/u/x", nil)
	r.AddCookie(&http.Cookie{Name: origRefCookie, Value: origRefEmpty})
	w := httptest.NewRecorder()
	g.HTTPMiddleware(mux).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("a direct visit must not redirect, got %d", w.Code)
	}
}

// Mode "both": the redirect carries the parameter AND the landing page gets
// the shim.
func TestRefererModeBoth(t *testing.T) {
	g := guardWithMode(t, "both")

	w := serveWithStash(t, g, "http://example.com/u/x")
	if w.Code != http.StatusFound {
		t.Fatalf("want a redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if u, err := url.Parse(loc); err != nil || u.Query().Get("bg_ref") != "https://yandex.ru/" {
		t.Fatalf("bad redirect target: %q", loc)
	}

	w2 := serveWithStash(t, g, loc)
	if w2.Code != 200 {
		t.Fatalf("after redirect: status %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), `return "https://yandex.ru/"`) {
		t.Errorf("both mode must also inject the shim:\n%s", w2.Body.String())
	}
}
