// Checkbox stage, between proof-of-work and captcha. The checkbox itself
// verifies nothing: it holds the visitor while the page collects signals
// (automation traces, pointer activity, environment). No third party is
// involved. Canvas and WebGL are not collected: they enable cross-site
// tracking and are not needed to spot headless browsers.
package botguard

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

// checkboxToken carries the signed challenge data.
type checkboxToken struct {
	Nonce string `json:"n"`
	TS    int64  `json:"t"`
	UAH   string `json:"u"`
	FP    string `json:"f"`
	FPK   string `json:"k"`
}

// checkboxEnv is what the page reports.
type checkboxEnv struct {
	Webdriver  bool   `json:"wd"` // navigator.webdriver
	Automation string `json:"au"` // Puppeteer/Selenium/Playwright traces found
	Moved      bool   `json:"mv"` // pointer moved or screen touched
	DwellMS    int    `json:"dw"` // milliseconds on the page before the click
	TZ         string `json:"tz"` // timezone
	Lang       string `json:"lg"` // browser language
	Cores      int    `json:"hc"` // hardwareConcurrency
	Mem        int    `json:"dm"` // deviceMemory
	Touch      int    `json:"tp"` // maxTouchPoints
	W, H       int    `json:"-"`  // screen
	ScreenW    int    `json:"sw"`
	ScreenH    int    `json:"sh"`
	Plugins    int    `json:"pl"` // plugin count
	UAPlat     string `json:"pf"` // navigator.platform
}

// suspicious returns why the client was rejected, or an empty string.
func (e checkboxEnv) suspicious() string {
	switch {
	case e.Webdriver:
		return "webdriver"
	case e.Automation != "":
		return "automation:" + e.Automation
	// Faster than a human reacts. Kept low: on mobile the finger is already
	// near the screen.
	case e.DwellMS > 0 && e.DwellMS < 150:
		return "too fast"
	// A 0x0 screen is typical of headless browsers. No lower bound, old
	// phones report 320 or less.
	case e.ScreenW <= 0 || e.ScreenH <= 0:
		return "bad screen"
	}
	// Pointer movement is not required: phones have no pointer.
	return ""
}

func (g *Guard) issueCheckbox(s Signals) string {
	t := checkboxToken{
		Nonce: randomNonce(), TS: g.cfg.now().UnixMilli(),
		UAH: s.UAHash, FP: s.FPrint, FPK: s.FPKind,
	}
	body, _ := json.Marshal(t)
	enc := base64.RawURLEncoding.EncodeToString(body)
	return enc + "." + g.sign(enc)
}

func (g *Guard) parseCheckboxToken(tok string) (checkboxToken, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return checkboxToken{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(g.signBytes(parts[0]), sig) {
		return checkboxToken{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return checkboxToken{}, false
	}
	var t checkboxToken
	if json.Unmarshal(raw, &t) != nil {
		return checkboxToken{}, false
	}
	return t, true
}

type checkboxPageData struct {
	Token      string
	VerifyPath string
	Title      string
	Host       string // site name in the heading
}

const defaultCheckboxHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>
 /* Styled after the familiar Cloudflare check so visitors are not alarmed. */
 *{box-sizing:border-box}
 body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
      margin:0;min-height:100vh;color:#313131;background:#fff;
      display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
 .wrap{width:100%;max-width:600px}
 h1{font-size:24px;font-weight:500;margin:0 0 6px;color:#313131}
 .host{font-size:15px;color:#555;margin:0 0 26px}
 .widget{border:1px solid #d9d9d9;border-radius:4px;background:#fafafa;
         padding:14px 16px;display:flex;align-items:center;gap:12px;
         max-width:302px;min-height:64px}
 .cb{width:24px;height:24px;border:2px solid #b6b6b6;border-radius:3px;background:#fff;
     flex:0 0 auto;display:grid;place-items:center;cursor:pointer;transition:.12s}
 .cb:hover{border-color:#8a8a8a}
 .cb.on{background:#2f7d32;border-color:#2f7d32}
 .cb svg{width:15px;height:15px;opacity:0;transition:.12s}
 .cb.on svg{opacity:1}
 .lbl{font-size:15px;color:#313131;cursor:pointer;user-select:none}
 .sp{width:24px;height:24px;border:3px solid #e2e2e2;border-top-color:#7a7a7a;
     border-radius:50%;animation:s .8s linear infinite;display:none;flex:0 0 auto}
 @keyframes s{to{transform:rotate(360deg)}}
 .busy .cb{display:none} .busy .sp{display:block}
 .brand{margin-left:auto;text-align:right;font-size:10px;color:#a0a0a0;line-height:1.3}
 .note{font-size:13px;color:#666;margin-top:26px;max-width:520px}
 .err{color:#b3261e;font-size:14px;margin-top:12px;min-height:18px}
</style></head>
<body><div class="wrap">
 <h1>{{.Host}}</h1>
 <p class="host">Verifying you are human. This will take a few seconds.</p>
 <div class="widget" id="card">
   <div class="cb" id="cb"><svg viewBox="0 0 16 16"><path d="M2 8.5l4 4 8-9" stroke="#fff"
     stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
   <div class="sp" id="sp"></div>
   <div class="lbl" id="lbl">Verify you are human</div>
 </div>
 <div class="err" id="err"></div>
 <p class="note">This check confirms the connection is secure and that you are not an
    automated program. It runs because activity from your network looked unusual.</p>
 <noscript><p class="note">JavaScript must be enabled to continue.</p></noscript>
</div>
<script>
(function(){
  var token = {{.Token}}, url = {{.VerifyPath}};
  var t0 = Date.now(), moved = false;
  // Any pointer activity suggests a human is present.
  ['mousemove','pointermove','touchstart','wheel','keydown'].forEach(function(ev){
    window.addEventListener(ev, function(){ moved = true; }, {once:true, passive:true});
  });

  function automationTraces(){
    var hits = [];
    // Traces left by common automation frameworks.
    var keys = ['__playwright','__puppeteer','__selenium','_phantom','callPhantom',
                '__nightmare','__webdriver_evaluate','__driver_evaluate',
                '__selenium_unwrapped','__fxdriver_evaluate','_Selenium_IDE_Recorder'];
    for (var i=0;i<keys.length;i++){ if (keys[i] in window) hits.push(keys[i]); }
    if (navigator.webdriver) hits.push('navigator.webdriver');
    try { if (window.document.documentElement.getAttribute('webdriver')) hits.push('attr'); } catch(e){}
    return hits.join(',');
  }

  var card = document.getElementById('card');
  card.addEventListener('click', function(){
    if (card.classList.contains('busy')) return;
    document.getElementById('cb').classList.add('on');
    setTimeout(function(){ card.classList.add('busy'); }, 180);

    var env = {
      wd: navigator.webdriver === true,
      au: automationTraces(),
      mv: moved,
      dw: Date.now() - t0,
      tz: (Intl.DateTimeFormat().resolvedOptions().timeZone || ''),
      lg: navigator.language || '',
      hc: navigator.hardwareConcurrency || 0,
      dm: navigator.deviceMemory || 0,
      tp: navigator.maxTouchPoints || 0,
      sw: screen.width || 0, sh: screen.height || 0,
      pl: (navigator.plugins ? navigator.plugins.length : 0),
      pf: navigator.platform || ''
    };
    fetch(url, {method:'POST', credentials:'same-origin',
      headers:{'content-type':'application/json'},
      body: JSON.stringify({token: token, env: env})
    }).then(function(res){
      if (res.ok) {
        // Clear the flag so the next check may retry automatically.
        try { sessionStorage.removeItem('bg_retried'); } catch(e) {}
        location.reload();
        return;
      }
      // Do not ask the visitor to refresh: the usual cause is an expired
      // token, and a fresh page issues a new one. One automatic retry, then
      // a link, so a failing check does not loop forever.
      if (!sessionStorage.getItem('bg_retried')) {
        try { sessionStorage.setItem('bg_retried', '1'); } catch(e) {}
        document.getElementById('err').textContent = 'Retrying…';
        setTimeout(function(){ location.reload(); }, 900);
        return;
      }
      card.classList.remove('busy');
      document.getElementById('cb').classList.remove('on');
      document.getElementById('err').innerHTML =
        'Verification failed. <a href="" onclick="sessionStorage.removeItem(\'bg_retried\');' +
        'location.reload();return false;">Try again</a>';
    }).catch(function(){
      // Network blip: retry once on our own.
      card.classList.remove('busy');
      document.getElementById('cb').classList.remove('on');
      document.getElementById('err').textContent = 'Connection problem, retrying…';
      setTimeout(function(){ location.reload(); }, 1500);
    });
  });
})();
</script></body></html>`

func (g *Guard) renderCheckbox(w http.ResponseWriter, s Signals) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(g.cfg.Challenge.StatusCode)
	_ = g.checkboxTmpl.Execute(w, checkboxPageData{
		Token:      g.issueCheckbox(s),
		VerifyPath: g.cfg.Challenge.CheckboxPath,
		Title:      g.cfg.Challenge.Title,
		Host:       s.Host,
	})
	g.recordFP(s, fpEvent{challenged: 1})
}

type checkboxRequest struct {
	Token string      `json:"token"`
	Env   checkboxEnv `json:"env"`
}

var _ = template.HTML("") // template is parsed in New()
