package botguard

import (
	"testing"
)

// TestClassifyUA checks the UA maps and the check order against reference
// user agents.
func TestClassifyUA(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want UAKind
		bot  string // expected bot name ("" — not checked)
	}{
		// ── search engines: must go to the ASN check, not to the blacklist ──
		{"googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			UAKnownBot, "Googlebot"},
		{"googleother", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0 Mobile Safari/537.36 (compatible; GoogleOther)",
			UAKnownBot, "GoogleOther"},
		{"google-read-aloud", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0 Mobile Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)",
			UAKnownBot, "Google-Read-Aloud"},
		{"baiduspider", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
			UAKnownBot, "Baiduspider"},
		{"bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			UAKnownBot, "Bingbot"},
		{"yandexbot", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
			UAKnownBot, "YandexBot"},
		{"applebot", "Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
			UAKnownBot, "Applebot"},
		{"sogou", "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
			UAKnownBot, "Sogou web spider"},
		// Render bots fetch JS/CSS; they must stay known bots.
		{"baidu_render", "Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)",
			UAKnownBot, "Baiduspider"},
		// baiduboxapp is the Baidu app with a person behind it, not a bot.
		{"baiduboxapp_is_human", "Mozilla/5.0 (Linux; Android 12; baiduboxapp) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
			UABrowser, ""},
		{"yandex_render", "Mozilla/5.0 (compatible; YandexRenderResourcesBot/1.0; +http://yandex.com/bots)",
			UAKnownBot, "YandexBot"},
		{"yandex_images", "Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)",
			UAKnownBot, "YandexBot"},
		// Yandex Browser is a browser; no generic "yandex" match.
		{"yabrowser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 YaBrowser/24.1.0 Safari/537.36",
			UABrowser, ""},
		// Meta crawlers put their marker at the end of a browser UA.
		{"meta_webindexer", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
			UABehavioral, "meta-webindexer"},

		// ── social previews: no ASN of their own, judged by behavior ──
		// mileusna parses this UA as Name="Safari"; matched by substring.
		{"facebook_preview", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0",
			UABehavioral, "facebookexternalhit"},
		{"telegram", "TelegramBot (like TwitterBot)", UABehavioral, ""},
		{"discord", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
			UABehavioral, "Discordbot"},

		// ── AI crawlers: allowed by default ──
		{"exasearchbot", "Mozilla/5.0 (compatible; ExaSearchBot/1.0; +https://crawler.exa.ai)",
			UAAIBot, "ExaSearchBot"},
		{"gptbot", "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.1; +https://openai.com/gptbot)",
			UAAIBot, "GPTBot"},
		{"claudebot", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
			UAAIBot, "ClaudeBot"},
		// user-initiated fetches, same list
		{"claude-user", "Mozilla/5.0 (compatible; Claude-User/1.0; +https://www.anthropic.com/claude-user)",
			UAAIBot, "Claude-User"},
		{"chatgpt-user", "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
			UAAIBot, "ChatGPT-User"},

		// ── Headless Chrome: behavioral, not blacklisted by name ──
		{"headless_chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/150.0.0.0 Safari/537.36",
			UABehavioral, "Headless Chrome"},

		// ── SEO scrapers: blacklist ──
		{"ahrefs", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			UABadBot, "AhrefsBot"},
		{"semrush", "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
			UABadBot, "SemrushBot"},
		{"mj12", "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
			UABadBot, "MJ12bot"},
		{"dotbot", "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
			UABadBot, "DotBot"},

		// ── tools: blacklist ──
		{"curl", "curl/8.14.1", UAToolAgent, ""},
		{"wget", "Wget/1.21.3", UAToolAgent, ""},
		{"python", "python-requests/2.31.0", UAToolAgent, ""},
		{"scrapy", "Scrapy/2.11 (+https://scrapy.org)", UAToolAgent, ""},

		// ── real people: left alone ──
		{"chrome_win", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			UABrowser, ""},
		{"safari_ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			UABrowser, ""},
		{"firefox_linux", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
			UABrowser, ""},
		{"chrome_android", "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
			UABrowser, ""},

		// ── empty UA ──
		{"empty", "", UAEmpty, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, bot := classifyUAlib(c.ua)
			if got != c.want {
				t.Errorf("UA kind: got %s, want %s (bot=%q)", got, c.want, bot)
			}
			if c.bot != "" && bot != c.bot {
				t.Errorf("bot name: got %q, want %q", bot, c.bot)
			}
		})
	}
}

// TestBotASNCoverage checks that every known bot has at least one ASN and
// that the ASNs the crawlers actually come from are present.
func TestBotASNCoverage(t *testing.T) {
	for name, asns := range botASN {
		if len(asns) == 0 {
			t.Errorf("bot %q is in botASN with no ASN at all", name)
		}
	}
	// Baidu and Sogou crawl through carrier backbones, Yandex also from
	// Direct Cursus; dropping one of these blocks a real search engine.
	required := map[string][]uint32{
		"Googlebot":         {15169},
		"GoogleOther":       {15169},
		"Google-Read-Aloud": {15169},
		"Baiduspider":       {4837, 55967}, // 4837 is the backbone
		"Sogou web spider":  {4837, 56046, 146966, 140293},
		"Bingbot":           {8075},
		"YandexBot":         {13238, 212066},
		"Applebot":          {714},
	}
	for name, needed := range required {
		have := map[uint32]bool{}
		for _, a := range botASN[name] {
			have[a] = true
		}
		for _, a := range needed {
			if !have[a] {
				t.Errorf("critical: %q is missing ASN %d — the real bot will be blacklisted", name, a)
			}
		}
	}
}

// TestKnownUASubstrOrder checks that more specific substrings come before the
// generic ones, otherwise "googlebot-image" is recognized as "googlebot".
func TestKnownUASubstrOrder(t *testing.T) {
	idx := map[string]int{}
	for i, k := range knownUASubstr {
		idx[k.sub] = i
	}
	pairs := [][2]string{
		{"googlebot-image", "googlebot"},
		{"googlebot-video", "googlebot"},
		{"googlebot-news", "googlebot"},
		{"sogou web spider", "sogou"},
	}
	for _, p := range pairs {
		spec, gen := idx[p[0]], idx[p[1]]
		if spec > gen {
			t.Errorf("%q must come before %q (currently %d > %d)", p[0], p[1], spec, gen)
		}
	}
}

// TestNoOverlapBlacklistKnown checks that a bot is never both blacklisted and
// known/AI: the outcome would then depend on the order of the checks.
func TestNoOverlapBlacklistKnown(t *testing.T) {
	for name := range seoBlacklist {
		if _, ok := botASN[name]; ok {
			t.Errorf("%q is in both seoBlacklist and botASN", name)
		}
		if aiCrawlers[name] {
			t.Errorf("%q is in both seoBlacklist and aiCrawlers", name)
		}
		if socialCloud[name] {
			t.Errorf("%q is in both seoBlacklist and socialCloud", name)
		}
	}
}

// BlockAI switches AI crawlers between allow and block.
func TestBlockAICrawlers(t *testing.T) {
	old := blockAICrawlers
	defer func() { blockAICrawlers = old }()

	gptbot := "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"
	claudeUser := "Mozilla/5.0 (compatible; Claude-User/1.0; +https://www.anthropic.com/claude-user)"

	blockAICrawlers = false
	if k, _ := classifyUAlib(gptbot); k != UAAIBot {
		t.Errorf("BlockAI=false: GPTBot should pass, got %s", k)
	}

	blockAICrawlers = true
	if k, _ := classifyUAlib(gptbot); k != UABadBot {
		t.Errorf("BlockAI=true: GPTBot should be blocked, got %s", k)
	}
	// Claude-User lives in the same list, so the ban covers it too.
	if k, _ := classifyUAlib(claudeUser); k != UABadBot {
		t.Errorf("BlockAI=true: Claude-User is in aiCrawlers too, got %s", k)
	}
}

// Params.Limits override the dimension defaults.
func TestLimitsFromParams(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.Limits = map[string]float64{"fp@host": 50, "ip_ua@host": 999}

	cfg := NewConfig(p)
	got := map[string]float64{}
	for _, d := range cfg.Dimensions {
		got[d.Name] = d.Limit
	}
	if got["fp@host"] != 50 {
		t.Errorf("fp@host = %v, want 50 from Params", got["fp@host"])
	}
	if got["ip_ua@host"] != 999 {
		t.Errorf("ip_ua@host = %v, want 999 from Params", got["ip_ua@host"])
	}
	// dimensions not listed in Limits keep their default
	if got["subnet"] == 0 {
		t.Error("subnet lost its limit: unlisted dimensions must keep the default")
	}
}
