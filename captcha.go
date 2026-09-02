// Character-entry captcha, shown to clients well past the limits
// (Thresholds.CaptchaAt): proof-of-work is cheap for a botnet, a captcha
// costs a human or OCR per request. It filters simple networks only;
// modern solvers read this kind of captcha well.
package botguard

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"strings"
)

// captchaAlphabet excludes look-alike characters (0/O, 1/I/l).
const captchaAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const captchaLen = 5

// captchaToken holds the signed data. The answer lives inside the token
// rather than on the server, same as the proof-of-work challenge.
type captchaToken struct {
	Code string `json:"c"` // expected answer
	// Dest is the page the visitor was heading to; Referer is lost on a
	// retry, which is submitted from /__bg/captcha.
	Dest string `json:"d"`
	TS   int64  `json:"t"`
	UAH  string `json:"u"`
	FP   string `json:"f"`
	FPK  string `json:"k"`
}

// newCaptchaCode generates the code. math/rand is enough: the code lives
// for seconds and is HMAC-protected.
func newCaptchaCode(r *rand.Rand) string {
	var b strings.Builder
	for i := 0; i < captchaLen; i++ {
		b.WriteByte(captchaAlphabet[r.Intn(len(captchaAlphabet))])
	}
	return b.String()
}

// issueCaptcha returns a signed token and the SVG image.
func (g *Guard) issueCaptcha(s Signals, dest string) (token, svg string) {
	r := rand.New(rand.NewSource(g.cfg.now().UnixNano() + int64(len(s.IPStr))))
	code := newCaptchaCode(r)

	t := captchaToken{
		Code: code, Dest: dest, TS: g.cfg.now().UnixMilli(),
		UAH: s.UAHash, FP: s.FPrint, FPK: s.FPKind,
	}
	body, _ := json.Marshal(t)
	enc := base64.RawURLEncoding.EncodeToString(body)
	return enc + "." + g.sign(enc), renderCaptchaSVG(code, r)
}

// parseCaptchaToken verifies the signature and expiry.
func (g *Guard) parseCaptchaToken(tok string) (captchaToken, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return captchaToken{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(g.signBytes(parts[0]), sig) {
		return captchaToken{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return captchaToken{}, false
	}
	var t captchaToken
	if json.Unmarshal(raw, &t) != nil {
		return captchaToken{}, false
	}
	return t, true
}

// renderCaptchaSVG draws the code with rotation, offset and noise. SVG
// avoids font and image dependencies.
func renderCaptchaSVG(code string, r *rand.Rand) string {
	const w, h = 190, 62
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="captcha">`, w, h, w, h)
	b.WriteString(`<rect width="100%" height="100%" fill="#f4f4f6"/>`)

	for i := 0; i < 5; i++ {
		x1, y1 := r.Intn(w), r.Intn(h)
		x2, y2 := r.Intn(w), r.Intn(h)
		fmt.Fprintf(&b, `<path d="M%d %d Q%d %d %d %d" stroke="#%02x%02x%02x" `+
			`stroke-width="%d" fill="none" opacity="0.45"/>`,
			x1, y1, r.Intn(w), r.Intn(h), x2, y2,
			120+r.Intn(90), 120+r.Intn(90), 120+r.Intn(90), 1+r.Intn(2))
	}

	// each glyph gets its own rotation, size and vertical offset
	step := (w - 30) / captchaLen
	for i, ch := range code {
		x := 18 + i*step + r.Intn(6) - 3
		y := 42 + r.Intn(10) - 5
		rot := r.Intn(46) - 23
		size := 30 + r.Intn(8)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-family="Georgia,serif" font-size="%d" `+
			`font-weight="bold" fill="#%02x%02x%02x" transform="rotate(%d %d %d)">%c</text>`,
			x, y, size, r.Intn(80), r.Intn(80), r.Intn(80), rot, x, y, ch)
	}

	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, `<circle cx="%d" cy="%d" r="%d" fill="#888" opacity="0.35"/>`,
			r.Intn(w), r.Intn(h), 1+r.Intn(2))
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// captchaPageData feeds the captcha page template.
type captchaPageData struct {
	Token string
	// SVG is inserted as markup; it is generated from a fixed alphabet, so
	// no user input reaches it.
	SVG        template.HTML
	VerifyPath string
	Title      string
	Error      string
}

const defaultCaptchaHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>
 body{font:16px/1.6 system-ui,-apple-system,sans-serif;display:grid;place-items:center;
      min-height:100vh;margin:0;color:#2c2c2c;background:#fafafa}
 .box{text-align:center;max-width:400px;padding:32px}
 .cap{margin:18px auto 14px;border:1px solid #ddd;border-radius:6px;
      background:#fff;display:inline-block;line-height:0}
 input{font:18px ui-monospace,monospace;padding:10px 12px;width:170px;text-align:center;
       text-transform:uppercase;border:1px solid #ccc;border-radius:6px}
 button{font:16px system-ui;padding:10px 20px;margin-left:6px;border:none;border-radius:6px;
        background:#2c6fbb;color:#fff;cursor:pointer}
 .err{color:#c0392b;margin-top:10px}
 small{color:#888;display:block;margin-top:14px}
</style></head>
<body><div class="box">
 <h2>Confirm you are human</h2>
 <p>Enter the characters shown below.</p>
 <div class="cap">{{.SVG}}</div>
 <form method="post" action="{{.VerifyPath}}">
  <input type="hidden" name="ct" value="{{.Token}}">
  <input name="code" autocomplete="off" autocapitalize="characters"
         autofocus maxlength="8" required>
  <button type="submit">Continue</button>
 </form>
 {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
 <small>This check appears when traffic from your network looks automated.</small>
</div></body></html>`

// renderCaptcha serves the page; a non-empty errMsg marks a retry after a
// wrong answer.
func (g *Guard) renderCaptcha(w http.ResponseWriter, s Signals, dest, errMsg string) {
	token, svg := g.issueCaptcha(s, dest)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(g.cfg.Challenge.StatusCode)
	_ = g.captchaTmpl.Execute(w, captchaPageData{
		Token:      token,
		SVG:        template.HTML(svg),
		VerifyPath: g.cfg.Challenge.CaptchaPath,
		Title:      g.cfg.Challenge.Title,
		Error:      errMsg,
	})
	g.recordFP(s, fpEvent{challenged: 1})
}

// safeDest keeps only same-site relative paths outside /__bg/, so the
// redirect is neither open nor a bounce back to the challenge.
func safeDest(u string) string {
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		p := strings.IndexByte(u[i+3:], '/')
		if p < 0 {
			return ""
		}
		u = u[i+3+p:]
	}
	if !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") {
		return ""
	}
	if strings.HasPrefix(u, "/__bg/") {
		return ""
	}
	return u
}
