// setup.go holds the bot classification and the Params-based configuration.
package botguard

import (
	"database/sql"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mileusna/useragent"
	"github.com/redis/go-redis/v9"
	"github.com/x-way/crawlerdetect"
)

// botASN maps a bot name (mileusna.Name) to its official ASNs.
var botASN = map[string][]uint32{
	"Googlebot": {15169}, "Google Ads Bot": {15169},
	"GoogleOther": {15169}, "Google-Read-Aloud": {15169},
	"Google-InspectionTool": {15169}, "Google-Favicon": {15169},
	"Googlebot-Image": {15169}, "Googlebot-Video": {15169}, "Googlebot-News": {15169},
	"Mediapartners-Google": {15169}, "AdsBot-Google": {15169},
	"Bingbot": {8075},
	// Yandex also crawls from Direct Cursus networks (212066, 207304).
	"YandexBot":   {13238, 208722, 212066, 207304, 210546},
	"YandexAdNet": {13238, 208722, 212066, 207304, 210546},
	"Applebot":    {714, 6185},
	// Baidu and Sogou crawl through carrier backbones (China Unicom 4837,
	// China Telecom), not through networks of their own.
	"Baiduspider":      {55967, 38365, 23724, 4837, 4808, 58593, 38627},
	"Sogou web spider": {4808, 4837, 56046, 134756, 146966, 140293, 4134},
	"coccocbot":        {18403, 7552, 45899},
	"SeznamBot":        {43037},        // Seznam.cz
	"Qwantbot":         {199064, 2200}, // Qwant
	"PetalBot":         {136907, 55990, 45102},
	// Meta crawlers also come through partner networks; see socialUASubstr.
	"meta-webindexer":      {32934},
	"meta-externalagent":   {32934},
	"meta-externalfetcher": {32934},
	// facebookexternalhit, Twitterbot and Pinterest are in socialCloud: they
	// arrive via CDN partners and mobile networks, so an ASN check gives
	// false impostors.
	"TelegramBot": {62041},
	"LinkedInBot": {14413}, "vkShare": {47541, 47542},
}

var seoBlacklist = map[string]bool{
	"AhrefsBot": true, "SemrushBot": true, "MJ12bot": true, "DotBot": true,
	// PetalBot is not here: Petal Search is a search engine, not an SEO scraper.
	"BLEXBot": true, "DataForSeoBot": true, "SerpstatBot": true,
	"MegaIndex": true, "SEOkicks": true, "BacklinksExtendedBot": true,
	// brand-mention monitoring
	"AwarioBot": true, "AwarioSmartBot": true, "AwarioRssBot": true,
}

var aiCrawlers = map[string]bool{
	"GPTBot": true, "OAI-SearchBot": true, "ClaudeBot": true, "anthropic-ai": true,
	"Bytespider": true, "CCBot": true, "meta-externalagent": true, "Amazonbot": true,
	"PerplexityBot": true, "Google-Extended": true, "Applebot-Extended": true,
	// AI search engines
	"ExaSearchBot": true,
	"YouBot":       true, "Diffbot": true, "ImagesiftBot": true, "cohere-ai": true,
	"Timpibot": true, "Omgilibot": true, "Webzio-Extended": true,
	// Claude-User / ChatGPT-User are user-initiated fetches, not training
	// crawlers.
	"Claude-User": true, "Claude-SearchBot": true,
	"ChatGPT-User": true, "OAI-SearchBot-User": true,
	// The wire name is "Perplexity-User", not the "PerplexityBot-User" from
	// their docs.
	"PerplexityBot-User": true, "Perplexity-User": true,
}

var toolAgents = []string{
	"lightpanda", // headless browser built for scrapers and agents
	"curl/", "wget", "python-requests", "python-urllib", "go-http-client",
	"java/", "apache-httpclient", "okhttp", "scrapy", "libwww-perl",
	"masscan", "httpie", "axios/", "node-fetch", "guzzlehttp", "aiohttp",
	"postmanruntime", "insomnia",
}

// socialCloud holds preview bots and crawlers with no ASN of their own. They
// are judged by behavior: a quiet one passes, a flood hits the rate limits.
var socialCloud = map[string]bool{
	"Discordbot": true, "Slackbot": true, "WhatsApp": true,
	"SkypeUriPreview": true, "DuckDuckBot": true,
	// arrive via Cloudflare/Akamai/mobile networks
	"facebookexternalhit": true, "facebookcatalog": true,
	"Twitterbot": true, "Pinterest": true,
	// Headless Chrome (mileusna's name, with a space) covers both preview
	// services and scrapers, so it takes the common scoring path.
	"Headless Chrome": true,
}

// techAllowlist holds UA substrings of real browsers that crawlerdetect or
// mileusna mistake for bots.
var techAllowlist = []string{
	"yandexsmartcamera", // photo search in the Yandex app
	"baiduboxapp",       // the Baidu mobile app
	"yabrowser",         // Yandex Browser
	"miuibrowser",       // the Xiaomi browser
}

// matchTrustedIP reports an exact match, or a prefix match for entries ending
// in a dot (e.g. "192.168." covers the whole network).
func matchTrustedIP(ip string, list []string) bool {
	for _, t := range list {
		if ip == t {
			return true
		}
		if strings.HasSuffix(t, ".") && strings.HasPrefix(ip, t) {
			return true
		}
	}
	return false
}

// knownUASubstr maps a lowercased UA substring to a bot name from botASN.
// Order matters: more specific entries come first (googlebot-image before
// googlebot).
var knownUASubstr = []struct{ sub, name string }{
	{"googlebot-image", "Googlebot-Image"},
	{"googlebot-video", "Googlebot-Video"},
	{"googlebot-news", "Googlebot-News"},
	{"google-inspectiontool", "Google-InspectionTool"},
	{"google-read-aloud", "Google-Read-Aloud"},
	{"google-favicon", "Google-Favicon"},
	{"googleother", "GoogleOther"},
	{"mediapartners-google", "Mediapartners-Google"},
	{"adsbot-google", "AdsBot-Google"},
	{"googlebot", "Googlebot"},
	{"baiduspider-render", "Baiduspider"},
	{"baiduspider", "Baiduspider"},
	// No baiduboxapp: that is the Baidu mobile app, a real person.
	{"sogou web spider", "Sogou web spider"},
	{"sogou", "Sogou web spider"},
	{"coccocbot", "coccocbot"},
	// YandexRenderResourcesBot fetches JS/CSS; cutting it off makes Yandex
	// see the site without styles.
	{"yandexrenderresourcesbot", "YandexBot"},
	{"yandexaccessibilitybot", "YandexBot"},
	{"yandeximages", "YandexBot"},
	{"yandexvideo", "YandexBot"},
	{"yandexmedia", "YandexBot"},
	{"yandexmobilebot", "YandexBot"},
	{"yadirectfetcher", "YandexBot"},
	{"yandexbot", "YandexBot"},
	// No generic "yandex": it would catch user-facing apps such as
	// yandexsmartcamera.
	{"bingbot", "Bingbot"},
	{"applebot", "Applebot"},
	{"seznambot", "SeznamBot"},
	{"qwantbot", "Qwantbot"},
	{"petalbot", "PetalBot"},
	// Social previews are handled earlier by matchSocialByUA.
}

// socialUASubstr holds social previews that mileusna does not name
// (facebookexternalhit, for instance, hides behind Name="Safari").
var socialUASubstr = []struct{ sub, name string }{
	{"facebookexternalhit", "facebookexternalhit"},
	{"facebookcatalog", "facebookcatalog"},
	{"facebot", "facebookexternalhit"},
	// Meta crawlers put their marker at the end of a plain Chrome UA, so
	// mileusna sees a browser.
	{"meta-webindexer", "meta-webindexer"},
	{"meta-externalagent", "meta-externalagent"},
	{"meta-externalfetcher", "meta-externalfetcher"},
	{"twitterbot", "Twitterbot"},
	{"telegrambot", "TelegramBot"},
	{"discordbot", "Discordbot"},
	{"slackbot", "Slackbot"},
	{"whatsapp", "WhatsApp"},
	{"skypeuripreview", "SkypeUriPreview"},
	{"linkedinbot", "LinkedInBot"},
	{"pinterest", "Pinterest"},
	{"vkshare", "vkShare"},
	{"redditbot", "redditbot"},
}

// matchSocialByUA looks up a preview bot by UA substring (l is lowercased).
func matchSocialByUA(l string) string {
	for _, k := range socialUASubstr {
		if strings.Contains(l, k.sub) {
			return k.name
		}
	}
	return ""
}

// matchKnownByUA looks up a known bot by UA substring (l is already lowercased).
func matchKnownByUA(l string) string {
	for _, k := range knownUASubstr {
		if strings.Contains(l, k.sub) {
			return k.name
		}
	}
	return ""
}

// matchAIByUA looks up an AI crawler by UA substring (l is lowercased).
func matchAIByUA(l string) string {
	for name := range aiCrawlers {
		if strings.Contains(l, strings.ToLower(name)) {
			return name
		}
	}
	return ""
}

// matchBadByUA looks up a blacklisted bot by UA substring (l is lowercased).
func matchBadByUA(l string) string {
	for name := range seoBlacklist {
		if strings.Contains(l, strings.ToLower(name)) {
			return name
		}
	}
	return ""
}

// classifyUAlib combines mileusna and crawlerdetect. It returns the kind and the
// bot name.
func classifyUAlib(ua string) (UAKind, string) {
	if strings.TrimSpace(ua) == "" {
		return UAEmpty, ""
	}
	p := useragent.Parse(ua)
	name := p.Name
	l := strings.ToLower(ua)

	// Custom rules override the built-in maps.
	if r := matchRules(customRules, ua, name); r != nil {
		return r.kindOf()
	}
	// In override mode the built-in lists are not consulted at all.
	if customRulesMode == RulesOverride {
		return UABrowser, ""
	}

	for _, t := range techAllowlist {
		if t != "" && strings.Contains(l, strings.ToLower(t)) {
			return UABrowser, ""
		}
	}
	if socialCloud[name] {
		return UABehavioral, name // a quiet one passes, a flood hits the rate limits
	}
	// mileusna parses "…Safari/601 facebookexternalhit/1.1" as Name="Safari",
	// so social previews are also matched by substring.
	if n := matchSocialByUA(l); n != "" {
		return UABehavioral, n
	}
	// A known bot by mileusna's name, or by substring for the ones it does
	// not name (GoogleOther, Baiduspider), which crawlerdetect below would
	// take for a tool.
	if _, ok := botASN[name]; ok {
		return UAKnownBot, name
	}
	if n := matchKnownByUA(l); n != "" {
		return UAKnownBot, n
	}
	if aiCrawlers[name] {
		if blockAICrawlers {
			return UABadBot, name
		}
		return UAAIBot, name
	}
	// Same by substring: "… compatible; GPTBot/1.2" parses as a browser.
	if n := matchAIByUA(l); n != "" {
		if blockAICrawlers {
			return UABadBot, n
		}
		return UAAIBot, n
	}
	if seoBlacklist[name] {
		return UABadBot, name
	}
	if n := matchBadByUA(l); n != "" {
		return UABadBot, n
	}
	for _, t := range toolAgents {
		if strings.Contains(l, t) {
			return UAToolAgent, name
		}
	}
	if crawlerdetect.IsCrawler(ua) {
		return UAToolAgent, name
	}
	if p.Bot {
		return UAUnknownBot, name
	}
	return UABrowser, ""
}

// Params holds the installation-specific configuration: stores, paths,
// thresholds, mode, logger.
type Params struct {
	Redis redis.UniversalClient // counters and state; required
	DB    *sql.DB               // fingerprint stats; nil disables the store

	Enforce bool // true blocks, false only counts and logs
	// Disabled switches the guard off entirely; takes precedence over
	// Enforce.
	Disabled bool
	// TrackingCookie names a cookie with a random per-browser id, set on
	// first contact, for following one browser through the frontend log.
	// Empty disables it.
	TrackingCookie string
	// SharedScoreDims lists dimensions whose key covers many unrelated
	// clients; they challenge but never block and never revoke a clearance.
	// nil keeps the default: fp@host, asn_fp@host, asn.
	SharedScoreDims []string
	// RefererMode is how the recovered traffic source reaches client-side
	// analytics: "inject" (default) shims document.referrer in the first HTML
	// page after a pass, "param" redirects once adding the source as a query
	// parameter, "off" restores only the Referer header.
	RefererMode string
	// RefererParam is the query parameter for RefererMode="param";
	// empty means "bg_ref".
	RefererParam string
	// StatsMaxBytes caps how much of the log tail the stats page reads.
	// 0 keeps the default of 2 GB.
	StatsMaxBytes int64
	// LogAllowed also logs visitors that pass. Off by default.
	LogAllowed bool
	LogPath    string // where verdicts are written (for the stats page)
	Secret     string // HMAC for tokens and cookies, at least 16 bytes
	StoreDSN   string // stats table, e.g. "ja4.bg_fingerprints"
	// StoreDialect is the SQL flavour of the stats database: "mysql",
	// "postgres" or "sqlite". Empty auto-detects from the driver.
	StoreDialect string

	// Scoring thresholds.
	ChallengeAt float64  // score at which the PoW challenge is shown
	CheckboxAt  float64  // score at which the checkbox is shown (0 = off)
	HardReasons []string // reasons that show the checkbox immediately
	// BlockAI bans AI crawlers (GPTBot, ClaudeBot, Bytespider, CCBot and
	// others); false lets them through and counts them.
	BlockAI   bool
	CaptchaAt float64 // score at which the CAPTCHA is shown (0 = off)
	BlockAt   float64 // score at which the request is blocked

	// Rules are the project's own bot rules, checked before the built-in
	// maps. See RulesMode.
	Rules     []Rule
	RulesMode RulesMode

	// Limits are the rate-dimension limits (requests per Window per key).
	// An empty map keeps the defaults.
	// Names: ip_ua, ip, subnet, ip_ua@host, ip@host, subnet@host,
	//        fp@host, asn_fp@host, asn
	Limits map[string]float64

	// StatsUser / StatsPassword guard /__bg/stats with Basic Auth. Empty
	// leaves the page open; it shows visitor IPs and User-Agents.
	StatsUser     string
	StatsPassword string

	// Logger receives events; see logger.go. nil disables logging.
	Logger Logger

	// Challenge (PoW).
	BaseDifficulty int           // zero bits in the SHA-256; +1 bit doubles the work
	MaxDifficulty  int           // difficulty ceiling
	ClearanceTTL   time.Duration // how long the pass lasts after a solution
	TokenTTL       time.Duration // how long an issued token lives

	Window      time.Duration // window of the rate counters
	TrustedASN  []uint32      // networks where a datacenter means real people (WARP etc.)
	TrustedIPs  []string      // own addresses: they bypass the guard entirely
	ContactHTML string        // contact shown on the refusal page
	Behavior    bool          // behavioral layer (a second Redis call per request)
	SampleRate  float64       // share of requests that reach the MySQL stats
}

// DefaultParams returns the default parameters.
func DefaultParams() Params {
	return Params{
		Enforce:     true,
		ChallengeAt: 1.0,
		// An ordinary visitor sees a quick PoW, a suspicious one the checkbox.
		CheckboxAt: 6.0,
		// Fingerprint dimensions show the checkbox regardless of score: a
		// client spread over thousands of IPs never produces a high multiple.
		HardReasons: []string{"score:fp@host", "score:fp", "score:asn_fp@host"},
		BlockAI:     false,
		// Requests per minute per dimension key; tune from your own traffic.
		Limits: map[string]float64{
			"ip_ua":       200,
			"ip":          400,
			"subnet":      2500,
			"ip_ua@host":  120,
			"ip@host":     250,
			"subnet@host": 1500,
			"fp@host":     200,
			"fp":          2000,
			"asn_fp@host": 900,
			"asn":         5000,
		},
		// The captcha is off; the checkbox covers its role.
		CaptchaAt:      0,
		BlockAt:        20.0,
		BaseDifficulty: 15,
		MaxDifficulty:  17,
		ClearanceTTL:   1 * time.Hour,
		TokenTTL:       180 * time.Second,
		Window:         time.Minute,
		TrustedASN:     []uint32{13335}, // Cloudflare WARP / iCloud Private Relay
		// Local only; the application adds its own monitoring addresses.
		TrustedIPs: []string{"127.0.0.1", "::1"},
		Behavior:   true,
		SampleRate: 1.0,
	}
}

// blockAICrawlers is the AI-crawler mode, set from Params.BlockAI.
var blockAICrawlers bool

// Custom rules and their mode, from Params.Rules/RulesMode.
var (
	customRules     []Rule
	customRulesMode RulesMode
	customBotASN    map[string][]uint32
)

func NewConfig(p Params) Config {
	blockAICrawlers = p.BlockAI
	customRules, customRulesMode = p.Rules, p.RulesMode
	customBotASN = map[string][]uint32{}
	for _, r := range p.Rules {
		if r.Action == RuleKnownBot && len(r.ASNs) > 0 {
			n := r.BotName
			if n == "" {
				n = r.Name
			}
			if n == "" {
				n = r.Match
			}
			customBotASN[n] = r.ASNs
		}
	}
	cfg := DefaultConfig([]byte(p.Secret))

	cfg.TrackingCookie = p.TrackingCookie
	cfg.SharedScoreDims = p.SharedScoreDims
	cfg.RefererMode = RefererMode(p.RefererMode)
	cfg.RefererParam = p.RefererParam
	cfg.LogAllowed = p.LogAllowed
	cfg.Mode = ModeMonitor
	if p.Enforce {
		cfg.Mode = ModeEnforce
	}
	if p.Disabled {
		cfg.Mode = ModeOff
		// Nothing reaches the database either.
		cfg.Store.Enabled = false
		cfg.Store.DB = nil
	}
	cfg.Window = p.Window
	cfg.Thresholds.ChallengeAt = p.ChallengeAt
	cfg.Thresholds.CheckboxAt = p.CheckboxAt
	cfg.Thresholds.HardReasons = p.HardReasons
	cfg.Thresholds.CaptchaAt = p.CaptchaAt
	cfg.Thresholds.BlockAt = p.BlockAt
	cfg.Challenge.BaseDifficulty = p.BaseDifficulty
	cfg.Challenge.MaxDifficulty = p.MaxDifficulty
	cfg.Challenge.TokenTTL = p.TokenTTL
	cfg.Challenge.ContactHTML = template.HTML(p.ContactHTML)
	cfg.ClearanceTTL = p.ClearanceTTL

	cfg.Network.TrustedASN = p.TrustedASN

	cfg.Headers = HeaderConfig{
		IP: "X-Real-IP", ForwardedFor: "X-Forwarded-For", JA4: "X-JA4",
		ASN: "X-ASN", ASNOrg: "X-Organization", UsageType: "X-Usertype",
		ConnectionType: "X-Connectiontype", Country: "X-COUNTRYCODE",
	}

	cfg.ClassifyUA = classifyUAlib
	// ASNs from custom rules override the built-in map.
	merged := make(map[string][]uint32, len(botASN)+len(customBotASN))
	for k, v := range botASN {
		merged[k] = v
	}
	for k, v := range customBotASN {
		merged[k] = v
	}
	cfg.BotASN = merged
	cfg.Dimensions = dimensionsB()
	// Limits from Params override the ones baked into dimensionsB.
	for i := range cfg.Dimensions {
		if v, ok := p.Limits[cfg.Dimensions[i].Name]; ok && v > 0 {
			cfg.Dimensions[i].Limit = v
		}
	}

	// Own addresses bypass the guard entirely.
	trusted := p.TrustedIPs
	cfg.SkipFunc = func(r *http.Request) bool {
		ip := strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if ip == "" {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if i := strings.IndexByte(xff, ','); i > 0 {
					ip = strings.TrimSpace(xff[:i])
				} else {
					ip = strings.TrimSpace(xff)
				}
			}
		}
		return matchTrustedIP(ip, trusted)
	}

	// Catches slow scrapers by rhythm and catalog walking.
	cfg.Behavior.Enabled = p.Behavior

	// Stats store: connection and table name come from Params.
	cfg.Store.Enabled = p.DB != nil && p.StoreDSN != ""
	cfg.Store.DB = p.DB
	cfg.Store.Table = p.StoreDSN
	cfg.Store.Dialect = Dialect(p.StoreDialect)
	cfg.Store.SampleRate = p.SampleRate
	cfg.Store.MaxBatch = 200

	cfg.Logger = p.Logger

	return cfg
}

func dimensionsB() []Dimension {
	return []Dimension{
		// GLOBAL
		{Name: "ip_ua", Limit: 200,
			Key: func(s Signals) string { return s.IPStr + "|" + s.UAHash }},
		{Name: "ip", Limit: 400, Aggregate: true,
			Key: func(s Signals) string { return s.IPStr }},
		// No fp_subnet: on carriers and CGNAT one client spans dozens of /24s,
		// so the dimension is either blind or hits real users.
		{Name: "subnet", Limit: 2500, Aggregate: true,
			Key: func(s Signals) string { return s.Subnet }},
		// PER-HOST (softer)
		{Name: "ip_ua@host", Limit: 120,
			Key: func(s Signals) string { return s.Host + "|" + s.IPStr + "|" + s.UAHash }},
		{Name: "ip@host", Limit: 250, Aggregate: true,
			Key: func(s Signals) string { return s.Host + "|" + s.IPStr }},
		{Name: "subnet@host", Limit: 1500, Aggregate: true,
			Key: func(s Signals) string { return s.Host + "|" + s.Subnet }},
		// A botnet or proxy pool spreads over thousands of IPs, one or two
		// requests each, but shares a TLS stack. The fingerprint is counted
		// per host without the subnet; for real users the same Chrome is
		// spread over time, for a botnet it is a spike.
		{Name: "fp@host", Limit: 200, Aggregate: true, NeedFingerprint: true,
			Key: func(s Signals) string { return s.Host + "|" + s.FPrint }},

		// The same fingerprint across every host. A botnet spread over a
		// hundred sites stays under fp@host on each of them and adds up to
		// tens of thousands of requests a minute in total; one Chrome build
		// used by real people never comes close.
		{Name: "fp", Limit: 2000, Aggregate: true, NeedFingerprint: true, NoFactor: true,
			Key: func(s Signals) string { return s.FPrint }},

		// Distributed scraping from datacenters: many IPs across /24s, one
		// ASN, one fingerprint. HostingOnly, so carriers and CGNAT are
		// untouched.
		{Name: "asn_fp@host", Limit: 900, Aggregate: true, HostingOnly: true, NeedFingerprint: true,
			Key: func(s Signals) string {
				if s.ASN == 0 {
					return ""
				}
				return s.Host + "|as" + strconv.FormatUint(uint64(s.ASN), 10) + "|" + s.FPrint
			}},
		// hosting: the whole ASN, datacenters only
		{Name: "asn", Limit: 5000, Aggregate: true, HostingOnly: true,
			Key: func(s Signals) string {
				if s.ASN == 0 {
					return ""
				}
				return "as" + strconv.FormatUint(uint64(s.ASN), 10)
			}},
	}
}
