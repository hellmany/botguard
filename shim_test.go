package botguard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The Referer header must be fixed before the request reaches the app.
func TestHeaderRestoredForApp(t *testing.T) {
	g := testGuard(t)
	r := httptest.NewRequest("GET", "http://example.com/x", nil)
	r.Header.Set("Referer", "https://example.com/x")
	ck := testCookie("https://yandex.ru/")
	r.AddCookie(&ck)
	if got, ok := g.restoreOrigReferer(httptest.NewRecorder(), r, false); !ok || got != "https://yandex.ru/" {
		t.Fatalf("returned %q", got)
	}
	if r.Referer() != "https://yandex.ru/" {
		t.Fatalf("the app would see %q", r.Referer())
	}
}

func testCookie(v string) http.Cookie {
	return http.Cookie{Name: origRefCookie, Value: url.QueryEscape(v)}
}

func TestShimInjectedIntoHTML(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &refInjector{rw: rec, shim: refShim("https://yandex.ru/")}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(`<!doctype html><html><head><title>t</title></head><body>hi</body></html>`))

	body := rec.Body.String()
	at := strings.Index(body, "<head>")
	sh := strings.Index(body, "<script>")
	if sh < 0 || at < 0 || sh != at+len("<head>") {
		t.Fatalf("the shim must directly follow <head>, got:\n%s", body)
	}
	if !strings.Contains(body, `return "https://yandex.ru/"`) {
		t.Errorf("the source did not make it into the shim:\n%s", body)
	}
	if !strings.Contains(body, "<body>hi</body>") {
		t.Errorf("the page body was damaged:\n%s", body)
	}
}

// Non-HTML and encoded responses pass through byte for byte.
func TestShimLeavesOtherResponsesAlone(t *testing.T) {
	for _, tc := range []struct {
		ct, enc string
		code    int
	}{
		{"application/json", "", 200},
		{"text/html", "gzip", 200},
		{"text/html", "", 404},
	} {
		rec := httptest.NewRecorder()
		w := &refInjector{rw: rec, shim: refShim("https://x.com/")}
		w.Header().Set("Content-Type", tc.ct)
		if tc.enc != "" {
			w.Header().Set("Content-Encoding", tc.enc)
		}
		w.WriteHeader(tc.code)
		w.Write([]byte("<head>payload</head>"))
		if rec.Body.String() != "<head>payload</head>" {
			t.Errorf("%+v: response was modified: %q", tc, rec.Body.String())
		}
	}
}

// The cookie value is visitor-controlled; a </script> inside it must not be
// able to break out of the shim.
func TestShimEscapesScriptBreakout(t *testing.T) {
	s := string(refShim(`https://x.com/</script><script>alert(1)`))
	if strings.Contains(s, "</script><script>alert") {
		t.Fatalf("breakout possible: %s", s)
	}
}

// A first chunk with no <head> stays untouched.
func TestShimGivesUpWithoutHead(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &refInjector{rw: rec, shim: refShim("https://x.com/")}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte("plain fragment"))
	if rec.Body.String() != "plain fragment" {
		t.Errorf("modified: %q", rec.Body.String())
	}
}
