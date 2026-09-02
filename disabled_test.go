package botguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The zero Mode stays ModeMonitor.
func TestZeroModeIsMonitor(t *testing.T) {
	var m Mode
	if m != ModeMonitor {
		t.Fatalf("the zero Mode is %d, it must be ModeMonitor", m)
	}
	if ModeOff == ModeMonitor || ModeOff == ModeEnforce {
		t.Error("ModeOff collides with another mode")
	}
}

func TestDisabledSetsModeOff(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Enforce = true // Disabled must win
	p.Disabled = true
	cfg := NewConfig(p)
	if cfg.Mode != ModeOff {
		t.Errorf("Mode = %d, want ModeOff even with Enforce set", cfg.Mode)
	}
	if cfg.Store.Enabled || cfg.Store.DB != nil {
		t.Error("the statistics store must be off too")
	}
}

// A disabled guard passes the request through untouched, without verdict
// headers.
func TestDisabledPassesEverythingThrough(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Disabled = true
	g, err := New(nil, NewConfig(p))
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	g.RegisterMux(mux)
	reached := false
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte("ok"))
	})

	// A request that would normally be challenged outright.
	r := httptest.NewRequest("GET", "http://example.com/x", nil)
	r.Header.Set("X-Usertype", "hosting")
	r.Header.Set("User-Agent", "curl/8.0")
	w := httptest.NewRecorder()
	g.HTTPMiddleware(mux).ServeHTTP(w, r)

	if !reached {
		t.Fatal("the request did not reach the application")
	}
	if w.Code != 200 {
		t.Errorf("status %d, want 200", w.Code)
	}
	if h := w.Header().Get("X-BG-Decision"); h != "" {
		t.Errorf("a disabled guard still stamped a verdict: %q", h)
	}
}

// Register must not add the challenge endpoints when the guard is off.
func TestDisabledRegistersNoRoutes(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Disabled = true
	g, _ := New(nil, NewConfig(p))

	if n := len(g.Routes()); n != 0 {
		t.Errorf("%d routes registered, want none", n)
	}
}
