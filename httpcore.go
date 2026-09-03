package botguard

// The framework-agnostic core: plain net/http, so the guard works with the
// standard mux, chi, gorilla and anything built on http.Handler. The
// framework adapters are thin wrappers over this file.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// secureReq reports whether the request arrived over HTTPS, directly or via a
// proxy that forwards the scheme.
func secureReq(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

type verdictCtxKey struct{}

// VerdictFromRequest returns the verdict HTTPMiddleware stored on the request.
func VerdictFromRequest(r *http.Request) (Verdict, bool) {
	v, ok := r.Context().Value(verdictCtxKey{}).(Verdict)
	return v, ok
}

// httpError writes a small JSON error, matching what API clients expect.
func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"message":` + strconv.Quote(msg) + `}`))
}

func writeJSONOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// HTTPMiddleware is the guard as standard net/http middleware. In ModeOff it
// is a pass-through: no counters, no Redis, no log.
func (g *Guard) HTTPMiddleware(next http.Handler) http.Handler {
	if g.Disabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.shouldSkip(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Not r.Context(): a cancellation mid-command makes go-redis drop the
		// connection from the pool, which leaks descriptors under mass
		// disconnects.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		v := g.Evaluate(ctx, r)
		cancel()
		v.Enforced = g.cfg.Mode == ModeEnforce
		r = r.WithContext(context.WithValue(r.Context(), verdictCtxKey{}, v))
		g.logVerdict(v)
		if g.cfg.OnVerdict != nil {
			g.cfg.OnVerdict(v)
		}

		w.Header().Set("X-BG-Score", strconv.FormatFloat(v.Score, 'f', 2, 64))
		w.Header().Set("X-BG-Decision", v.Decision.String())

		// Before any branch: the first response, a challenge included,
		// carries the tracking id.
		g.ensureTrackingCookie(w, r, secureReq(r))

		if g.cfg.Mode == ModeMonitor {
			w.Header().Set("X-BG-Mode", "monitor")
			next.ServeHTTP(w, r)
			return
		}

		switch v.Decision {
		case Block:
			// A page for a human, JSON for XHR and API clients.
			if isAPIRequest(r) {
				httpError(w, http.StatusForbidden, "forbidden")
				return
			}
			g.renderDenied(w, http.StatusForbidden, v)
			return
		case TooMany:
			w.Header().Set("Retry-After", "60")
			if isAPIRequest(r) {
				httpError(w, http.StatusTooManyRequests, "rate limited")
				return
			}
			g.renderDenied(w, http.StatusTooManyRequests, v)
			return
		case Challenge:
			// XHR and fetch cannot show an HTML page; they get a 429.
			if isAPIRequest(r) {
				w.Header().Set("Retry-After", "10")
				httpError(w, http.StatusTooManyRequests, "challenge required")
				return
			}
			// Revoke the pass only for the visitor's own abuse. Behind a
			// shared exit (VPN, Tor) a neighbour's score keeps re-challenging
			// everyone, and wiping the cookie there would undo every solve.
			if v.Cleared && strings.HasPrefix(v.Reason, "cleared_abuse") {
				http.SetCookie(w, ClearCookie())
			}
			// Stash the traffic source; it is restored once the visitor is
			// through (see origRefCookie).
			g.saveOrigReferer(w, r, secureReq(r))

			// The stage rises with the score.
			eff := g.effChallengeScore(v)
			if g.cfg.Thresholds.CaptchaAt > 0 && eff >= g.cfg.Thresholds.CaptchaAt {
				g.renderCaptcha(w, v.Signals, r.URL.RequestURI(), "")
				return
			}
			if g.cfg.Thresholds.CheckboxAt > 0 &&
				(eff >= g.cfg.Thresholds.CheckboxAt || g.isHardReason(v.Reason)) {
				g.renderCheckbox(w, v.Signals)
				return
			}
			g.renderChallenge(w, v.Signals, eff)
			return
		}

		// The visitor is through: hand the traffic source back before the
		// application sees the request. Only here, so the challenge rounds
		// do not overwrite the stash with our own page.
		// In param mode redirect once with the source in the URL, keeping
		// the stash for the header restore on the request that follows.
		if (g.cfg.RefererMode == RefererQueryParam || g.cfg.RefererMode == RefererBoth) &&
			r.Method == http.MethodGet {
			if ck, err := r.Cookie(origRefCookie); err == nil && ck.Value != origRefEmpty {
				if ref := validRefererValue(ck.Value); ref != "" &&
					r.URL.Query().Get(g.refererParamName()) == "" {
					q := r.URL.Query()
					q.Set(g.refererParamName(), ref)
					u := *r.URL
					u.RawQuery = q.Encode()
					http.Redirect(w, r, u.String(), http.StatusFound)
					return
				}
			}
		}

		if ref, ok := g.restoreOrigReferer(w, r, secureReq(r)); ok {
			// The verdict was logged with the pre-restore referrer.
			if ref != v.Signals.Referer {
				g.logRefRestored(v, ref)
			}
			// document.referrer on this load is our own URL; shim it.
			switch g.cfg.RefererMode {
			case RefererInject, RefererBoth, "":
				w = &refInjector{rw: w, shim: refShim(ref)}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// VerifyHTTP serves the proof-of-work submission.
func (g *Guard) VerifyHTTP(w http.ResponseWriter, r *http.Request) {
	// The verify endpoints bypass the middleware, so the tracking id is
	// mirrored here as well.
	g.ensureTrackingCookie(w, r, secureReq(r))
	// Not r.Context(), see HTTPMiddleware.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := g.extract(r)

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	t, ok := g.parseToken(req.Token)
	if !ok {
		g.noteChallengeFail(ctx, s)
		httpError(w, http.StatusForbidden, "bad token")
		return
	}

	fail := func(msg string) {
		g.noteChallengeFail(ctx, s)
		g.fps.push(fpEvent{key: fpKey{Kind: t.FPK, FP: t.FP, UAHash: t.UAH}, failed: 1})
		g.logChallengeResult(false, msg, s)
		if g.cfg.OnChallengeResult != nil {
			g.cfg.OnChallengeResult(false, msg, s)
		}
		httpError(w, http.StatusForbidden, msg)
	}

	switch {
	case g.cfg.now().UnixMilli()-t.TS > g.cfg.Challenge.TokenTTL.Milliseconds():
		httpError(w, http.StatusForbidden, "expired")
		return
	case t.Bind != g.bindValue(s):
		// issued to another client
		fail("binding mismatch")
		return
	case !checkPoW(req.Token, req.Nonce, t.Diff):
		fail("bad proof")
		return
	case g.cfg.Challenge.RejectWebdriver && req.Env.Webdriver:
		fail("automation detected")
		return
	case !g.markTokenUsed(ctx, t.Nonce):
		httpError(w, http.StatusForbidden, "replay")
		return
	}

	if g.store.rdb != nil {
		g.store.rdb.Del(ctx, g.cfg.KeyPrefix+"cf:"+s.IPStr)
	}
	g.fps.push(fpEvent{key: fpKey{Kind: t.FPK, FP: t.FP, UAHash: t.UAH}, solved: 1})
	g.logChallengeResult(true, "solved", s)
	if g.cfg.OnChallengeResult != nil {
		g.cfg.OnChallengeResult(true, "solved", s)
	}
	g.issueClearance(w, s, secureReq(r))
	writeJSONOK(w)
}

// CheckboxHTTP serves the checkbox result submission.
func (g *Guard) CheckboxHTTP(w http.ResponseWriter, r *http.Request) {
	g.ensureTrackingCookie(w, r, secureReq(r))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := g.extract(r)

	var req checkboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	t, ok := g.parseCheckboxToken(req.Token)
	if !ok {
		g.noteChallengeFail(ctx, s)
		httpError(w, http.StatusForbidden, "bad token")
		return
	}
	if g.cfg.now().UnixMilli()-t.TS > g.cfg.Challenge.TokenTTL.Milliseconds() {
		httpError(w, http.StatusForbidden, "expired")
		return
	}
	// One token, one check.
	if !g.markTokenUsed(ctx, t.Nonce) {
		httpError(w, http.StatusForbidden, "replay")
		return
	}

	if why := req.Env.suspicious(); why != "" {
		g.noteChallengeFail(ctx, s)
		g.fps.push(fpEvent{key: fpKey{Kind: t.FPK, FP: t.FP, UAHash: t.UAH}, failed: 1})
		g.logChallengeResult(false, "checkbox:"+why, s)
		if g.cfg.OnChallengeResult != nil {
			g.cfg.OnChallengeResult(false, "checkbox:"+why, s)
		}
		httpError(w, http.StatusForbidden, "check failed")
		return
	}

	if g.store.rdb != nil {
		g.store.rdb.Del(ctx, g.cfg.KeyPrefix+"cf:"+s.IPStr)
	}
	g.fps.push(fpEvent{key: fpKey{Kind: t.FPK, FP: t.FP, UAHash: t.UAH}, solved: 1})
	g.logChallengeResult(true, "checkbox solved", s)
	if g.cfg.OnChallengeResult != nil {
		g.cfg.OnChallengeResult(true, "checkbox solved", s)
	}
	g.issueClearance(w, s, secureReq(r))
	writeJSONOK(w)
}

// CaptchaHTTP serves the captcha answer submission.
func (g *Guard) CaptchaHTTP(w http.ResponseWriter, r *http.Request) {
	g.ensureTrackingCookie(w, r, secureReq(r))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := g.extract(r)

	t, ok := g.parseCaptchaToken(r.FormValue("ct"))
	if !ok {
		g.noteChallengeFail(ctx, s)
		g.renderCaptcha(w, s, safeDest(r.Referer()), "Session expired, try again.")
		return
	}
	// The captcha lives as long as a proof-of-work token.
	if g.cfg.now().UnixMilli()-t.TS > g.cfg.Challenge.TokenTTL.Milliseconds() {
		g.renderCaptcha(w, s, t.Dest, "Session expired, try again.")
		return
	}
	answer := strings.ToUpper(strings.TrimSpace(r.FormValue("code")))
	if answer != t.Code {
		g.noteChallengeFail(ctx, s)
		g.fps.push(fpEvent{key: fpKey{Kind: t.FPK, FP: t.FP, UAHash: t.UAH}, failed: 1})
		g.logChallengeResult(false, "captcha wrong", s)
		if g.cfg.OnChallengeResult != nil {
			g.cfg.OnChallengeResult(false, "captcha wrong", s)
		}
		g.renderCaptcha(w, s, t.Dest, "Incorrect, please try again.")
		return
	}

	// Solved: clear the failure counter and issue a clearance.
	if g.store.rdb != nil {
		g.store.rdb.Del(ctx, g.cfg.KeyPrefix+"cf:"+s.IPStr)
	}
	g.fps.push(fpEvent{key: fpKey{Kind: t.FPK, FP: t.FP, UAHash: t.UAH}, solved: 1})
	g.logChallengeResult(true, "captcha solved", s)
	if g.cfg.OnChallengeResult != nil {
		g.cfg.OnChallengeResult(true, "captcha solved", s)
	}
	g.issueClearance(w, s, secureReq(r))
	back := safeDest(t.Dest)
	if back == "" {
		back = safeDest(r.Referer())
	}
	if back == "" {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// TestCheckboxHTTP shows the checkbox page without waiting to exceed a limit.
func (g *Guard) TestCheckboxHTTP(w http.ResponseWriter, r *http.Request) {
	g.renderCheckbox(w, g.extract(r))
}

// TestCaptchaHTTP shows the captcha page.
func (g *Guard) TestCaptchaHTTP(w http.ResponseWriter, r *http.Request) {
	g.renderCaptcha(w, g.extract(r), "/", "")
}

// TestChallengeHTTP shows the proof-of-work page, or a confirmation once the
// clearance cookie is set (otherwise location.reload() would spin forever).
func (g *Guard) TestChallengeHTTP(w http.ResponseWriter, r *http.Request) {
	s := g.extract(r)
	if g.hasClearance(r, s) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head>` +
			`<meta charset="utf-8"><title>Challenge passed</title></head>` +
			`<body style="font:16px system-ui;display:grid;place-items:center;min-height:100vh;margin:0">` +
			`<div style="text-align:center"><h2>&#10003; Challenge passed</h2>` +
			`<p>Clearance cookie is set. Delete cookie <code>` + ClearanceCookie +
			`</code> to test again.</p></div></body></html>`))
		return
	}
	g.renderChallenge(w, s, g.cfg.Thresholds.ChallengeAt+1)
}

// Route is one endpoint the guard needs: framework adapters register these on
// their router, RegisterMux does it for the standard mux.
type Route struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// Disabled reports ModeOff: the middleware is a pass-through and no routes
// should be registered.
func (g *Guard) Disabled() bool { return g.cfg.Mode == ModeOff }

// Routes lists the endpoints: the three verification POSTs, the test pages
// and the stats page. Empty in ModeOff.
func (g *Guard) Routes() []Route {
	if g.Disabled() {
		return nil
	}
	return []Route{
		{http.MethodPost, g.cfg.Challenge.VerifyPath, g.VerifyHTTP},
		{http.MethodPost, g.cfg.Challenge.CaptchaPath, g.CaptchaHTTP},
		{http.MethodPost, g.cfg.Challenge.CheckboxPath, g.CheckboxHTTP},
		{http.MethodGet, "/__bg/test-checkbox", g.TestCheckboxHTTP},
		{http.MethodGet, "/__bg/test-captcha", g.TestCaptchaHTTP},
		{http.MethodGet, "/__bg/test-challenge", g.TestChallengeHTTP},
		{http.MethodGet, "/__bg/stats", StatsHTTP},
		{http.MethodPost, "/__bg/stats/reset", StatsResetHTTP},
	}
}

func postOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h(w, r)
	}
}

// RegisterMux wires the guard's endpoints onto a standard mux. Wrap the root
// handler with HTTPMiddleware separately:
//
//	mux := http.NewServeMux()
//	g.RegisterMux(mux)
//	mux.Handle("/", myApp)
//	http.ListenAndServe(addr, g.HTTPMiddleware(mux))
//
// In ModeOff nothing is registered.
func (g *Guard) RegisterMux(mux *http.ServeMux) {
	for _, rt := range g.Routes() {
		h := rt.Handler
		if rt.Method == http.MethodPost {
			h = postOnly(h)
		}
		mux.HandleFunc(rt.Path, h)
	}
}

// ─── stats over plain net/http ───

func statsAuthOK(r *http.Request) bool {
	if bgStatsUser == "" && bgStatsPass == "" {
		return true // no password set
	}
	u, pw, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(u), []byte(bgStatsUser)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pw), []byte(bgStatsPass)) == 1
}

// requireStatsAuth returns 401 with a password prompt if the credentials do
// not match.
func requireStatsAuth(w http.ResponseWriter, r *http.Request) bool {
	if statsAuthOK(r) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="botguard stats"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// StatsResetHTTP serves POST /__bg/stats/reset and clears the verdict log.
// POST only, so a crawler cannot trigger it.
func StatsResetHTTP(w http.ResponseWriter, r *http.Request) {
	if !requireStatsAuth(w, r) {
		return
	}
	// Truncate rather than delete: the logger keeps the file open.
	if err := os.Truncate(bgLogPath, 0); err != nil {
		http.Error(w, "could not clear the log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// The pass-rate card is summed from the fingerprint table, so the log
	// alone is not enough: zero the counters too. The pairs and their
	// verdict labels stay — those are knowledge, not statistics.
	if bgStoreDB != nil {
		if _, err := bgStoreDB.Exec(`UPDATE ` + bgStoreTable +
			` SET hits = 0, challenged = 0, solved = 0, failed = 0`); err != nil {
			http.Error(w, "log cleared, but counters not: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	noteStatsReset()
	http.Redirect(w, r, "/__bg/stats?force=1", http.StatusSeeOther)
}

// StatsHTTP serves GET /__bg/stats.
func StatsHTTP(w http.ResponseWriter, r *http.Request) {
	if !requireStatsAuth(w, r) {
		return
	}
	hours := 1
	if v := r.URL.Query().Get("h"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 48 {
			hours = n
		}
	}
	st, err := collectBGStats(hours)
	if err != nil {
		http.Error(w, "could not read the log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Never cached, or the page looks stuck after a reset.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		b, _ := json.MarshalIndent(st, "", "  ")
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderBGStatsHTML(st)))
}
