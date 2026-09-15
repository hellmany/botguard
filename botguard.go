// Package botguard is adaptive bot protection for Go web servers: request
// rates across several dimensions, User-Agent and ASN classification, and
// proof-of-work or checkbox challenges for whoever looks suspicious.
//
// The core speaks plain net/http; see HTTPMiddleware, RegisterMux and Routes.
// Adapters for Echo, Gin and Fiber live in their own modules under echo/,
// gin/ and fiber/.
//
// Dependencies:
//   - Redis: counters and challenge state. Required.
//   - SQL (MySQL, PostgreSQL or SQLite): JA4/User-Agent pair statistics.
//     Optional, written asynchronously, never blocking a request.
//   - Frontend headers: IP, JA4, ASN, network type. No mmdb and no DNS at
//     runtime.
//
// Bot policy: known bots are checked against their ASNs, SEO scrapers are
// blocked, everything else is judged by rate and behaviour.
//
//	g, err := botguard.New(rdb, botguard.NewConfig(p))
//	mux := http.NewServeMux()
//	g.RegisterMux(mux)
//	http.ListenAndServe(addr, g.HTTPMiddleware(mux))
package botguard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ════════════════════════════════ CONFIG ════════════════════════════════

type Mode int

const (
	// ModeMonitor counts and logs but blocks nobody.
	ModeMonitor Mode = iota
	ModeEnforce
	// ModeOff disables the guard completely: the middleware becomes a
	// pass-through and no endpoints are registered.
	// Must stay last so the zero value remains ModeMonitor.
	ModeOff
)

// Action is what to do with a request.
type Action int

const (
	ActionAllow Action = iota
	ActionChallenge
	ActionBlock
	ActionRateLimit
)

func (a Action) String() string {
	switch a {
	case ActionChallenge:
		return "challenge"
	case ActionBlock:
		return "block"
	case ActionRateLimit:
		return "ratelimit"
	}
	return "allow"
}

type Config struct {
	Mode   Mode
	Secret []byte // HMAC for tokens and cookies, at least 16 bytes

	// Window is the window of the rate counters.
	Window time.Duration
	// KeyPrefix prefixes every key in Redis.
	KeyPrefix string

	Headers    HeaderConfig
	Dimensions []Dimension
	Thresholds Thresholds
	Behavior   BehaviorConfig
	Challenge  ChallengeConfig
	Network    NetworkPolicy
	Bots       BotPolicy
	Store      FingerprintStoreConfig

	ClearanceTTL  time.Duration
	ClearanceMult float64 // how much softer the limits are for cleared clients
	// ClearanceBindSubnet is deprecated and ignored; kept so existing configs
	// keep compiling.
	ClearanceBindSubnet bool

	// RefererMode is how the recovered traffic source reaches client-side
	// analytics; see the RefererMode constants. Empty means RefererInject.
	RefererMode RefererMode
	// RefererParam is the query parameter used by RefererQueryParam.
	// Empty means "bg_ref".
	RefererParam string
	// TrackingCookie names a cookie with a random per-browser id, set on
	// first contact (the challenge page included). The guard does not use
	// it; it exists so the frontend log can follow one browser through the
	// flow. Empty disables it.
	TrackingCookie string
	// SharedScoreDims lists dimensions whose key aggregates unrelated
	// clients (a fingerprint, an ASN). They challenge but never block and
	// never revoke a clearance. nil means fp@host, fp, asn_fp@host, asn.
	SharedScoreDims []string
	// LogAllowed also records verdicts for visitors that were let through.
	// Off by default, since allows dominate the log.
	LogAllowed bool
	// SkipPaths are prefixes that bypass the guard entirely.
	SkipPaths []string
	// SkipFunc is an arbitrary skip condition (logged-in users, for instance).
	SkipFunc func(*http.Request) bool

	// Logger is the application logger (see logger.go). nil disables logging.
	Logger    Logger
	OnVerdict func(Verdict)
	OnError   func(error)
	// OnChallengeResult is called when a challenge finishes. ok=false comes
	// with a reason: bad proof, expired, replay, automation detected.
	OnChallengeResult func(ok bool, reason string, s Signals)
	// FailOpen decides what happens when Redis is unavailable: let through (true)
	// or cut off (false).
	FailOpen bool

	// ClassifyUA is an external UA classifier (mileusna/crawlerdetect). When set
	// it replaces the built-in g.classifyUA. It returns the kind and the bot name
	// (the name is needed for the ASN check and for bot_name in MySQL).
	ClassifyUA func(ua string) (UAKind, string)
	// BotASN maps a bot name to its official ASNs. For UAKnownBot: a matching ASN
	// means our own bot (Allow), a mismatch means an impostor (Block through
	// OnASNMismatch).
	BotASN map[string][]uint32

	now func() time.Time
}

// HeaderConfig says which headers carry the signals. They are set by the
// frontend (nginx, haproxy, your own L7); an empty name disables the signal.
//
// The frontend must overwrite these headers, never pass them through from
// the client.
type HeaderConfig struct {
	IP                string // X-Real-IP
	ForwardedFor      string // X-Forwarded-For, used when IP is empty
	TrustedProxyCount int    // how many rightmost XFF addresses are ours
	JA4               string // empty -> the fingerprint comes from HTTP headers
	ASN               string // accepted as "15169" or "AS15169"
	ASNOrg            string
	UsageType         string // hosting|residential|cellular|business|...
	ConnectionType    string // Cellular|Corporate|Cable/DSL|Dialup
	Country           string
}

// DefaultHeaderConfig returns the names matching the current nginx setup:
//
//	proxy_set_header X-COUNTRYCODE    $geoip2_data_country_code;
//	proxy_set_header X-Organization   $organization;
//	proxy_set_header X-ASN            $geoip2_data_asn;
//	proxy_set_header X-Usertype       $geoip2_data_user_type;
//	proxy_set_header X-Connectiontype $geoip2_data_connection_type;
//	proxy_set_header X-Real-IP        $remote_addr;
//
// Case does not matter: http.Header.Get is case-insensitive.
//
// proxy_set_header replaces a client-supplied header of the same name, but
// only in locations where the directive is present.
func DefaultHeaderConfig() HeaderConfig {
	return HeaderConfig{
		IP:             "X-Real-IP",
		ForwardedFor:   "X-Forwarded-For",
		JA4:            "X-JA4",
		ASN:            "X-ASN",
		ASNOrg:         "X-Organization",
		UsageType:      "X-Usertype",
		ConnectionType: "X-Connectiontype",
		Country:        "X-COUNTRYCODE",
	}
}

type Thresholds struct {
	ChallengeAt float64 // score at which the PoW challenge is shown
	// CaptchaAt is the score at which a CAPTCHA replaces the PoW: PoW is cheap
	// for a botnet, a captcha costs a human or OCR per request. 0 disables it.
	CaptchaAt float64
	// CheckboxAt is the score at which the checkbox with its environment check
	// is shown, a stage between PoW and the captcha. 0 disables it.
	CheckboxAt float64
	// HardReasons are reason prefixes (e.g. "score:fp@host") that show the
	// checkbox regardless of the score. A client spread over thousands of IPs
	// produces a low overage multiple, so for such dimensions the fact that
	// they fired matters more than by how much.
	HardReasons               []string
	BlockAt                   float64 // score at which a 403 is returned
	ChallengeFailsBeforeBlock int64   // challenge failures before the IP is blocked
	ClearedAbuseRatio         float64 // fraction of BlockAt that revokes a clearance
	EmptyUAWeight             float64 // contribution of an empty User-Agent to the score
	MismatchWeight            float64 // contribution of a known bad JA4↔UA pair
}

// NetworkPolicy covers everything decided from the ASN and the network type.
type NetworkPolicy struct {
	// Factors are limit multipliers per X-ASN-Type value. <1 tightens, >1 relaxes.
	// Keys are lowercase.
	Factors map[string]float64
	// AggregateOnly lists the types whose multiplier applies only to aggregate
	// dimensions: one person stays one person behind a NAT.
	AggregateOnly map[string]bool
	// ConnFactors are multipliers per connection_type, used when user_type is
	// empty or unknown.
	ConnFactors map[string]float64
	// ConnAggregateOnly is the same rule for connection_type.
	ConnAggregateOnly map[string]bool
	// DefaultFactor applies to types absent from Factors.
	DefaultFactor float64

	BlockASN           []uint32 // 403, no questions asked
	AlwaysChallengeASN []uint32 // challenged regardless of rate
	TrustedASN         []uint32 // datacenter, but real people (WARP, Private Relay)

	// ChallengeHostingBrowsers always challenges a browser UA coming from
	// hosting; much of that traffic is people on a VPN.
	ChallengeHostingBrowsers bool
	// HostingTypes are the X-ASN-Type values treated as a datacenter.
	HostingTypes []string
}

func DefaultNetworkPolicy() NetworkPolicy {
	return NetworkPolicy{
		Factors: map[string]float64{
			"hosting":                  0.25, // four times stricter
			"content_delivery_network": 0.25,
			"data_center":              0.25,
			"cellular":                 6.0, // CGNAT: thousands of subscribers per address
			"business":                 4.0, // an office behind one external IP
			"government":               4.0,
			"college":                  4.0,
			"school":                   4.0,
			"library":                  4.0,
			"residential":              1.0,
		},
		AggregateOnly: map[string]bool{
			"cellular": true, "business": true, "government": true,
			"college": true, "school": true, "library": true,
		},
		// db-ip/MaxMind values: Cellular, Corporate, Cable/DSL, Dialup.
		ConnFactors: map[string]float64{
			"cellular":  6.0, // carrier CGNAT
			"corporate": 4.0, // office NAT
			"cable/dsl": 1.0,
			"dialup":    1.0,
		},
		ConnAggregateOnly:        map[string]bool{"cellular": true, "corporate": true},
		DefaultFactor:            1.0,
		ChallengeHostingBrowsers: true,
		HostingTypes:             []string{"hosting", "content_delivery_network", "data_center", "datacenter"},
	}
}

// BotPolicy is the policy for declared bots.
//
// By default everyone passes. Restrictions are opt-in: either through
// Known[].OnMatch (restrict a particular bot) or through Known[].ASNs (catch an
// impostor arriving from outside the bot's own networks).
type BotPolicy struct {
	// Known lists the bots whose official ASNs we know.
	Known []KnownBot
	// UnknownBots decides what to do with a UA that looks like a tool (curl,
	// requests, a scraper) but is not described in Known.
	// ActionAllow by default: bots pass.
	UnknownBots Action
	// UnknownBotLimit is a soft ceiling for such clients, requests per Window.
	// 0 means no limit.
	UnknownBotLimit float64
	// ToolAgents are the UA substrings that mark a client as a tool.
	ToolAgents []string
}

// KnownBot is a bot with a known set of ASNs.
type KnownBot struct {
	Name string
	// UAMatch holds User-Agent substrings (case-insensitive).
	UAMatch []string
	// ASNs are the bot's official autonomous systems. An empty list means the
	// ASN is not checked.
	ASNs []uint32
	// OnMatch is what to do when the UA and the ASN agree. Allow by default.
	// This is where particular bots get restricted: ActionRateLimit or
	// ActionBlock.
	OnMatch Action
	// OnASNMismatch is what to do when the UA claims a bot but the ASN belongs
	// to someone else. Block by default.
	OnASNMismatch Action
	// Limit is the request ceiling per Window when OnMatch=ActionRateLimit, or
	// simply flood protection. 0 means no limit.
	Limit float64
}

// DefaultKnownBots is the starting set. Verify the ASNs against your own
// traffic: Google and Microsoft have more than one network each.
func DefaultKnownBots() []KnownBot {
	return []KnownBot{
		{Name: "googlebot", UAMatch: []string{"googlebot", "adsbot-google", "storebot-google", "google-inspectiontool"},
			ASNs: []uint32{15169}, OnASNMismatch: ActionBlock, Limit: 6000},
		{Name: "bingbot", UAMatch: []string{"bingbot", "adidxbot", "msnbot"},
			ASNs: []uint32{8075}, OnASNMismatch: ActionBlock, Limit: 6000},
		{Name: "yandexbot", UAMatch: []string{"yandexbot", "yandexmetrika", "yandeximages"},
			ASNs: []uint32{13238, 208722}, OnASNMismatch: ActionBlock, Limit: 6000},
		{Name: "applebot", UAMatch: []string{"applebot"},
			ASNs: []uint32{714, 6185}, OnASNMismatch: ActionBlock, Limit: 3000},
	}
}

func DefaultToolAgents() []string {
	return []string{
		"curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
		"okhttp", "java/", "libwww-perl", "postmanruntime", "insomnia",
		"axios/", "node-fetch", "guzzlehttp", "httpie", "restsharp",
		"aiohttp", "scrapy", "feedly", "feedfetcher", "bot", "crawler", "spider",
	}
}

func DefaultConfig(secret []byte) Config {
	return Config{
		Mode:      ModeMonitor,
		Secret:    secret,
		Window:    time.Minute,
		KeyPrefix: "bg:",
		Headers:   DefaultHeaderConfig(),
		Thresholds: Thresholds{
			ChallengeAt: 1.0,
			// Rate alone is ambiguous (an office, a carrier with CGNAT), so
			// exceeding a limit yields a challenge; the block is for 20x, which
			// is no longer a NAT but a machine.
			BlockAt:                   20.0,
			ChallengeFailsBeforeBlock: 12,
			// With BlockAt=20 a cleared client is re-challenged at score 5.
			ClearedAbuseRatio: 0.25,
			EmptyUAWeight:     1.0,
			MismatchWeight:    2.5,
		},
		Dimensions: DefaultDimensions(),
		Behavior:   DefaultBehaviorConfig(),
		Challenge:  DefaultChallengeConfig(),
		Network:    DefaultNetworkPolicy(),
		Bots: BotPolicy{
			Known:       DefaultKnownBots(),
			UnknownBots: ActionAllow, // bots pass unless told otherwise
			ToolAgents:  DefaultToolAgents(),
		},
		Store: DefaultFingerprintStoreConfig(),
		// Long enough that a person is not asked again mid-session.
		ClearanceTTL:        1 * time.Hour,
		ClearanceMult:       5,
		ClearanceBindSubnet: true,
		SkipPaths:           []string{"/healthz", "/metrics", "/__bg/"},
		FailOpen:            true,
		now:                 time.Now,
	}
}

func (c *Config) validate() error {
	if len(c.Secret) < 16 {
		return errors.New("botguard: Secret must be at least 16 bytes")
	}
	if c.Window <= 0 {
		return errors.New("botguard: Window must be positive")
	}
	if c.Thresholds.BlockAt <= c.Thresholds.ChallengeAt {
		return errors.New("botguard: BlockAt must be greater than ChallengeAt")
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "bg:"
	}
	if c.ClearanceMult <= 0 {
		c.ClearanceMult = 1
	}
	if c.Network.DefaultFactor <= 0 {
		c.Network.DefaultFactor = 1
	}
	if c.now == nil {
		c.now = time.Now
	}
	return nil
}

// ═══════════════════════════════ SIGNALS ═══════════════════════════════

// Signals is everything known about a request. It is filled from headers and
// the URL only, without touching any external system.
type Signals struct {
	IP     net.IP
	IPStr  string
	Subnet string // /24 for IPv4, /64 for IPv6

	JA4    string // from the header; empty if the frontend did not set it
	UA     string
	UAHash string
	// Referer is what the application will see: after a challenge the
	// original source is restored here, not our own challenge page.
	Referer string
	HTTPFP  string // header-based fingerprint — the fallback when JA4 is empty
	FPrint  string // the working fingerprint: JA4 if present, otherwise HTTPFP
	FPKind  string // "ja4" | "http" | "none"

	ASN       uint32
	ASNOrg    string
	UsageType string // lowercase
	ConnType  string // lowercase: cellular|corporate|cable/dsl|dialup
	Country   string

	Path     string
	PathHash string
	Host     string // r.Host without the port — for per-host dimensions
	UAKind   UAKind
	Bot      *KnownBot // non-nil when the UA matched a known bot
}

type UAKind int

const (
	UABrowser    UAKind = iota
	UAKnownBot          // known bot (search engine / social preview) — ASN is checked
	UAToolAgent         // curl/wget/… → blacklist
	UABadBot            // SEO scraper → blacklist
	UAUnknownBot        // plain bot / AI crawler → let through, collect stats
	UABehavioral        // social preview without an ASN, Headless Chrome → judged by behavior
	UAEmpty             // no User-Agent at all
	// UAAIBot is an AI crawler (GPTBot, ClaudeBot): allowed, counted apart
	// from the unknowns. Keep last, the values are iota-based.
	UAAIBot
)

func (k UAKind) String() string {
	switch k {
	case UAKnownBot:
		return "known_bot"
	case UAToolAgent:
		return "tool"
	case UABadBot:
		return "bad_bot"
	case UAUnknownBot:
		return "unknown_bot"
	case UABehavioral:
		return "behavioral"
	case UAEmpty:
		return "empty_ua"
	case UAAIBot:
		return "ai_bot"
	}
	return "browser"
}

// isHosting reports a datacenter network based on the X-ASN-Type value.
func (g *Guard) isHosting(s Signals) bool {
	for _, t := range g.cfg.Network.HostingTypes {
		if s.UsageType == t {
			return true
		}
	}
	return false
}

// hostOnly strips :port from r.Host for the per-host keys.
func hostOnly(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[:i]
	}
	return h
}

func (g *Guard) extract(r *http.Request) Signals {
	h := g.cfg.Headers
	ua := r.UserAgent()

	ip := g.clientIP(r)
	s := Signals{
		IP:      ip,
		IPStr:   ipString(ip),
		Subnet:  subnetKey(ip),
		UA:      ua,
		UAHash:  shortHash(ua),
		Referer: r.Referer(),
		ASNOrg:  r.Header.Get(h.ASNOrg),
		// Some frontends send the country as X-COUNTRYFRONT instead.
		Country:   firstNonEmpty(r.Header.Get(h.Country), r.Header.Get("X-COUNTRYFRONT")),
		UsageType: strings.ToLower(strings.TrimSpace(r.Header.Get(h.UsageType))),
		ConnType:  strings.ToLower(strings.TrimSpace(r.Header.Get(h.ConnectionType))),
		Path:      r.URL.Path,
		Host:      hostOnly(r.Host),
	}
	s.PathHash = shortHash(r.URL.Path)
	s.ASN = parseASN(r.Header.Get(h.ASN))
	s.JA4 = strings.TrimSpace(r.Header.Get(h.JA4))
	s.HTTPFP = httpFingerprint(r)

	if g.trustedASN[s.ASN] {
		// A datacenter with real people behind it: WARP, Private Relay.
		s.UsageType = "residential"
	}

	// nginx substitutes "-" for an empty variable; treat it as no JA4,
	// otherwise all such traffic shares one fingerprint.
	if s.JA4 != "" && s.JA4 != "-" {
		s.FPrint, s.FPKind = s.JA4, "ja4"
	} else {
		s.JA4 = ""
		s.FPrint, s.FPKind = s.HTTPFP, "http"
	}

	s.UAKind, s.Bot = g.classifyUA(ua)
	return s
}

// parseASN accepts "15169", "AS15169", "as15169"; anything else yields 0.
func parseASN(v string) uint32 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	v = strings.TrimPrefix(strings.TrimPrefix(v, "AS"), "as")
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func (g *Guard) clientIP(r *http.Request) net.IP {
	h := g.cfg.Headers
	if h.IP != "" {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get(h.IP))); ip != nil {
			return ip
		}
	}
	if h.ForwardedFor != "" {
		if xff := r.Header.Get(h.ForwardedFor); xff != "" {
			parts := strings.Split(xff, ",")
			idx := len(parts) - 1 - h.TrustedProxyCount
			if idx < 0 {
				idx = 0
			}
			if ip := net.ParseIP(strings.TrimSpace(parts[idx])); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}

func subnetKey(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// httpFingerprint is the fallback fingerprint when JA4 is unavailable: the
// Accept-* headers are stable for real browsers and differ from what
// libraries send. Weaker than JA4, but needs nothing from the frontend.
func httpFingerprint(r *http.Request) string {
	var b strings.Builder
	b.WriteString(r.Proto)
	for _, k := range []string{"Accept", "Accept-Language", "Accept-Encoding",
		"Sec-Ch-Ua", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Upgrade-Insecure-Requests"} {
		b.WriteByte('|')
		b.WriteString(r.Header.Get(k))
	}
	b.WriteByte('|')
	b.WriteString(r.UserAgent())
	return shortHash(b.String())
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:12]
}

func (g *Guard) classifyUA(ua string) (UAKind, *KnownBot) {
	if g.cfg.ClassifyUA != nil {
		kind, name := g.cfg.ClassifyUA(ua)
		if name != "" {
			return kind, &KnownBot{Name: name, ASNs: g.cfg.BotASN[name]}
		}
		return kind, nil
	}
	if strings.TrimSpace(ua) == "" {
		return UAEmpty, nil
	}
	l := strings.ToLower(ua)
	for i := range g.cfg.Bots.Known {
		kb := &g.cfg.Bots.Known[i]
		for _, m := range kb.UAMatch {
			if strings.Contains(l, strings.ToLower(m)) {
				return UAKnownBot, kb
			}
		}
	}
	for _, t := range g.cfg.Bots.ToolAgents {
		if strings.Contains(l, t) {
			return UAToolAgent, nil
		}
	}
	return UABrowser, nil
}

// ════════════════════════════ DIMENSIONS ════════════════════════════

// Dimension is one dimension of the rate analysis. The score is the maximum
// across dimensions, not the sum: behind an office NAT both ip and subnet
// are high at once.
type Dimension struct {
	Name  string
	Limit float64 // requests per Window considered normal
	// NoFactor exempts the dimension from the network-type multipliers.
	NoFactor bool
	// Key produces the key value. An empty string means "skip this dimension".
	Key func(Signals) string
	// Aggregate marks a dimension that counts everyone behind a single address.
	// Only such dimensions get their limit raised by NAT and CGNAT.
	Aggregate bool
	// HostingOnly enables the dimension for datacenter ASNs only.
	HostingOnly bool
	// NeedFingerprint requires a non-empty Signals.FPrint.
	NeedFingerprint bool
}

func DefaultDimensions() []Dimension {
	return []Dimension{
		{
			Name: "ip_ua", Limit: 120, Aggregate: false,
			Key: func(s Signals) string { return s.IPStr + "|" + s.UAHash },
		},
		{
			Name: "ip", Limit: 300, Aggregate: true,
			Key: func(s Signals) string { return s.IPStr },
		},
		// The fingerprint is counted together with the subnet: a current Chrome
		// shares one JA4 across millions of people.
		{
			Name: "fp_subnet", Limit: 600, Aggregate: true, NeedFingerprint: true,
			Key: func(s Signals) string { return s.FPrint + "|" + s.Subnet },
		},
		{
			Name: "subnet", Limit: 2000, Aggregate: true,
			Key: func(s Signals) string { return s.Subnet },
		},
		// A whole ASN only makes sense for hosters; a residential ISP is too
		// large for one threshold.
		{
			Name: "asn", Limit: 5000, Aggregate: true, HostingOnly: true,
			Key: func(s Signals) string {
				if s.ASN == 0 {
					return ""
				}
				return "as" + strconv.FormatUint(uint64(s.ASN), 10)
			},
		},
		// Distributed scraping from a cloud: one stack, many IPs, one ASN.
		{
			Name: "asn_fp", Limit: 1500, Aggregate: true, HostingOnly: true, NeedFingerprint: true,
			Key: func(s Signals) string {
				if s.ASN == 0 {
					return ""
				}
				return "as" + strconv.FormatUint(uint64(s.ASN), 10) + "|" + s.FPrint
			},
		},
	}
}

// limitFactor is the limit multiplier for a dimension: user_type first, then
// connection_type.
func (g *Guard) limitFactor(d Dimension, s Signals) float64 {
	np := g.cfg.Network

	// NAT relaxation is about many people behind one address. The site-wide
	// fingerprint count spans every address and network, so the network type
	// of one request says nothing about it: a botnet coming mostly through
	// "business" ranges was getting a 4x limit for free. Per-host dimensions
	// keep the relaxation — phones behind carrier NAT need it.
	if d.NoFactor {
		return np.DefaultFactor
	}

	if s.UsageType != "" {
		if f, ok := np.Factors[s.UsageType]; ok {
			// NAT relaxation applies to aggregate dimensions only.
			if np.AggregateOnly[s.UsageType] && !d.Aggregate {
				return np.DefaultFactor
			}
			return f
		}
	}
	if s.ConnType != "" {
		if f, ok := np.ConnFactors[s.ConnType]; ok {
			if np.ConnAggregateOnly[s.ConnType] && !d.Aggregate {
				return np.DefaultFactor
			}
			return f
		}
	}
	return np.DefaultFactor
}

func (g *Guard) activeDimensions(s Signals) []Dimension {
	hosting := g.isHosting(s)
	out := make([]Dimension, 0, len(g.cfg.Dimensions))
	for _, d := range g.cfg.Dimensions {
		if d.HostingOnly && !hosting {
			continue
		}
		if d.NeedFingerprint && s.FPrint == "" {
			continue
		}
		if d.Key(s) == "" {
			continue
		}
		out = append(out, d)
	}
	return out
}

// ═══════════════════════════ REDIS: COUNTERS ═══════════════════════════

// rateLua is a sliding window over two buckets, the current one plus a
// weighted previous one: O(1) memory per key and one round trip for all
// dimensions.
const rateLua = `
local now  = tonumber(ARGV[1])
local win  = tonumber(ARGV[2])
local cur  = math.floor(now / win)
local frac = (now % win) / win
local incr = tonumber(ARGV[3])
local out  = {}
for i = 1, #KEYS do
  local ck = KEYS[i] .. ':' .. cur
  local c
  if incr == 1 then
    c = redis.call('INCR', ck)
    if c == 1 then redis.call('PEXPIRE', ck, win * 2) end
  else
    c = tonumber(redis.call('GET', ck) or '0')
  end
  local p = tonumber(redis.call('GET', KEYS[i] .. ':' .. (cur - 1)) or '0')
  out[i] = tostring(c + p * (1 - frac))
end
return out
`

// behaviorLua updates the request counter, the interval sums (for the
// variance) and a HyperLogLog of unique paths in one round trip.
const behaviorLua = `
local h, hll = KEYS[1], KEYS[2]
local now    = tonumber(ARGV[1])
local ttl    = tonumber(ARGV[2])
local path   = ARGV[3]
local maxgap = tonumber(ARGV[4])

local n    = redis.call('HINCRBY', h, 'n', 1)
local last = tonumber(redis.call('HGET', h, 'last') or '0')
local dn   = tonumber(redis.call('HGET', h, 'dn') or '0')
local dsum = tonumber(redis.call('HGET', h, 'dsum') or '0')
local dsq  = tonumber(redis.call('HGET', h, 'dsq') or '0')
if last > 0 then
  local d = now - last
  if d > 0 and d < maxgap then
    dn, dsum, dsq = dn + 1, dsum + d, dsq + d * d
    redis.call('HSET', h, 'dn', dn, 'dsum', dsum, 'dsq', dsq)
  end
end
redis.call('HSET', h, 'last', now)
redis.call('PEXPIRE', h, ttl)

local uniq = 0
if path ~= '' then
  redis.call('PFADD', hll, path)
  redis.call('PEXPIRE', hll, ttl)
  uniq = redis.call('PFCOUNT', hll)
end
return {tostring(n), tostring(dn), tostring(dsum), tostring(dsq), tostring(uniq)}
`

type store struct {
	rdb    redis.UniversalClient
	rate   *redis.Script
	behav  *redis.Script
	prefix string
}

// errNoRedis is returned when no Redis client is set; the guard then fails
// open.
var errNoRedis = errors.New("botguard: no redis client configured")

func (s *store) rates(ctx context.Context, dims []Dimension, sig Signals,
	window time.Duration, now time.Time, incr bool) (map[string]float64, error) {

	if s.rdb == nil {
		return nil, errNoRedis
	}
	if len(dims) == 0 {
		return map[string]float64{}, nil
	}
	keys := make([]string, len(dims))
	for i, d := range dims {
		keys[i] = s.prefix + "r:" + d.Name + ":" + d.Key(sig)
	}
	incrArg := 0
	if incr {
		incrArg = 1
	}
	raw, err := s.rate.Run(ctx, s.rdb, keys,
		now.UnixMilli(), window.Milliseconds(), incrArg).StringSlice()
	if err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(raw))
	for i, v := range raw {
		f, _ := strconv.ParseFloat(v, 64)
		out[dims[i].Name] = f
	}
	return out, nil
}

// BehaviorStats is the accumulated behavior of a single client.
type BehaviorStats struct {
	N           float64
	IntervalN   float64
	IntervalSum float64
	IntervalSq  float64
	UniquePaths float64
}

// PathDiversity is the share of unique paths. Close to 1 means walking the
// catalog; close to 0 with a large N means hammering a single endpoint.
func (b BehaviorStats) PathDiversity() float64 {
	if b.N == 0 {
		return 0
	}
	return b.UniquePaths / b.N
}

// IntervalCV is the coefficient of variation of the intervals between requests.
// A human clicks unevenly (usually > 0.5), a timer in a script does not.
func (b BehaviorStats) IntervalCV() float64 {
	if b.IntervalN < 2 {
		return math.Inf(1)
	}
	mean := b.IntervalSum / b.IntervalN
	if mean <= 0 {
		return math.Inf(1)
	}
	variance := b.IntervalSq/b.IntervalN - mean*mean
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance) / mean
}

func (s *store) behavior(ctx context.Context, identity string, sig Signals,
	ttl, maxGap time.Duration, now time.Time) (BehaviorStats, error) {

	if s.rdb == nil {
		return BehaviorStats{}, errNoRedis
	}
	raw, err := s.behav.Run(ctx, s.rdb,
		[]string{s.prefix + "b:" + identity, s.prefix + "p:" + identity},
		now.UnixMilli(), ttl.Milliseconds(), sig.PathHash, maxGap.Milliseconds(),
	).StringSlice()
	if err != nil {
		return BehaviorStats{}, err
	}
	if len(raw) < 5 {
		return BehaviorStats{}, nil
	}
	p := func(i int) float64 { f, _ := strconv.ParseFloat(raw[i], 64); return f }
	return BehaviorStats{N: p(0), IntervalN: p(1), IntervalSum: p(2),
		IntervalSq: p(3), UniquePaths: p(4)}, nil
}

// ═════════════════════════════ BEHAVIOR ═════════════════════════════

// BehaviorConfig is the behavioral layer. It catches residential proxies,
// where both the IP and the browser are genuine, by path diversity and
// request rhythm.
type BehaviorConfig struct {
	Enabled bool
	TTL     time.Duration // accumulation window, longer than the rate one
	MaxGap  time.Duration // longer intervals do not count toward the rhythm

	// Walking the catalog: almost every path is different.
	CrawlEnabled bool
	CrawlMinReq  float64
	CrawlAbove   float64
	CrawlWeight  float64

	// Hammering a single endpoint.
	HammerEnabled bool
	HammerMinReq  float64
	HammerBelow   float64
	HammerWeight  float64

	// Machine-like interval rhythm: a slow scraper stays under every rate
	// threshold but gives itself away by even spacing.
	RhythmEnabled bool
	RhythmMinN    float64
	RhythmCVBelow float64
	RhythmWeight  float64
}

func DefaultBehaviorConfig() BehaviorConfig {
	return BehaviorConfig{
		Enabled: true,
		TTL:     10 * time.Minute,
		MaxGap:  30 * time.Second,

		CrawlEnabled: true,
		CrawlMinReq:  50,
		CrawlAbove:   0.92,
		CrawlWeight:  1.0,

		HammerEnabled: true,
		HammerMinReq:  150,
		HammerBelow:   0.03,
		HammerWeight:  0.8,

		RhythmEnabled: true,
		RhythmMinN:    25,
		RhythmCVBelow: 0.18,
		RhythmWeight:  1.5,
	}
}

type BehaviorHit struct {
	Rule   string
	Weight float64
}

func (g *Guard) behaviorScore(b BehaviorStats) (float64, []BehaviorHit) {
	c := g.cfg.Behavior
	if !c.Enabled {
		return 0, nil
	}
	var total float64
	var hits []BehaviorHit
	add := func(rule string, w float64) {
		total += w
		hits = append(hits, BehaviorHit{Rule: rule, Weight: w})
	}

	if c.CrawlEnabled && b.N >= c.CrawlMinReq && b.PathDiversity() > c.CrawlAbove {
		add("crawl_pattern", c.CrawlWeight)
	}
	if c.HammerEnabled && b.N >= c.HammerMinReq && b.PathDiversity() < c.HammerBelow {
		add("single_endpoint", c.HammerWeight)
	}
	if c.RhythmEnabled && b.IntervalN >= c.RhythmMinN && b.IntervalCV() < c.RhythmCVBelow {
		add("machine_rhythm", c.RhythmWeight)
	}
	return total, hits
}

// ═══════════════════ MYSQL: JA4 ↔ USER-AGENT PAIR STORE ═══════════════════

// FingerprintStoreConfig controls the collection of fingerprint/UA pair
// statistics. The table accumulates observations; pairs later marked
// verdict='bad' add weight to the score. Writes are asynchronous and
// batched, a request never waits on the database.
type FingerprintStoreConfig struct {
	Enabled bool
	// DB is a connection from your pool. You import the driver yourself; the
	// package does not depend on it.
	DB *sql.DB
	// Table is the table name; see SchemaSQL / SchemaFor for the DDL.
	Table string
	// Dialect is the SQL flavour: mysql, postgres or sqlite. Empty means
	// auto-detect from the driver behind DB.
	Dialect Dialect
	// FlushInterval is how often the accumulated rows are flushed.
	FlushInterval time.Duration
	// BufferSize is the size of the event channel; on overflow events are
	// dropped rather than block a request.
	BufferSize int
	// MaxBatch is the maximum number of rows in one INSERT.
	MaxBatch int
	// ReloadBadEvery is how often the verdict='bad' pairs are reloaded.
	// 0 disables reloading (bad pairs then take no part in scoring).
	ReloadBadEvery time.Duration
	// SampleRate is the share of requests that reach the statistics, 0..1.
	SampleRate float64
	// WriteTimeout is the timeout for a single batch.
	WriteTimeout time.Duration
}

func DefaultFingerprintStoreConfig() FingerprintStoreConfig {
	return FingerprintStoreConfig{
		Enabled:        false,
		Table:          "bg_fingerprints",
		FlushInterval:  10 * time.Second,
		BufferSize:     4096,
		MaxBatch:       500,
		ReloadBadEvery: 5 * time.Minute,
		SampleRate:     1.0,
		WriteTimeout:   5 * time.Second,
	}
}

// SchemaSQL is the table DDL. Run it once by hand.
const SchemaSQL = `
CREATE TABLE IF NOT EXISTS bg_fingerprints (
  fp_kind     ENUM('ja4','http')  NOT NULL,
  fingerprint VARCHAR(64)         NOT NULL,
  ua_hash     CHAR(16)            NOT NULL,
  ua          VARCHAR(512)        NOT NULL,
  ua_family   VARCHAR(24)         NOT NULL DEFAULT '',
  last_asn    INT UNSIGNED        NOT NULL DEFAULT 0,
  last_cc     CHAR(2)             NOT NULL DEFAULT '',
  last_type   VARCHAR(32)         NOT NULL DEFAULT '',
  hits        BIGINT UNSIGNED     NOT NULL DEFAULT 0,
  challenged  BIGINT UNSIGNED     NOT NULL DEFAULT 0,
  solved      BIGINT UNSIGNED     NOT NULL DEFAULT 0,
  failed      BIGINT UNSIGNED     NOT NULL DEFAULT 0,
  verdict     ENUM('unknown','good','bad') NOT NULL DEFAULT 'unknown',
  first_seen  DATETIME            NOT NULL,
  last_seen   DATETIME            NOT NULL,
  PRIMARY KEY (fp_kind, fingerprint, ua_hash),
  KEY idx_verdict (verdict),
  KEY idx_last_seen (last_seen),
  KEY idx_family (ua_family, fp_kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Useful queries for labelling later:
--
-- Fingerprints arriving with too many different UAs (agent rotation):
--   SELECT fingerprint, COUNT(*) c, SUM(hits) h FROM bg_fingerprints
--   WHERE fp_kind='ja4' GROUP BY fingerprint HAVING c > 50 ORDER BY h DESC;
--
-- Pairs that never solve the challenge (not browsers):
--   SELECT * FROM bg_fingerprints
--   WHERE challenged > 100 AND solved = 0 ORDER BY challenged DESC;
--
-- A UA family with a suspiciously rare fingerprint:
--   SELECT fingerprint, ua_family, SUM(hits) h FROM bg_fingerprints
--   GROUP BY fingerprint, ua_family HAVING h < 10;
`

type fpKey struct {
	Kind   string
	FP     string
	UAHash string
}

type fpEvent struct {
	key    fpKey
	ua     string
	family string
	asn    uint32
	cc     string
	utype  string
	// exactly one of the counters is 1
	hit, challenged, solved, failed uint64
}

type fpAgg struct {
	ua                               string
	family                           string
	asn                              uint32
	cc                               string
	utype                            string
	hits, challenged, solved, failed uint64
	last                             time.Time
}

type fingerprintStore struct {
	cfg    FingerprintStoreConfig
	onErr  func(error)
	events chan fpEvent
	stop   chan struct{}
	done   chan struct{}

	badMu sync.RWMutex
	bad   map[fpKey]struct{}

	dropped uint64
	dropMu  sync.Mutex
}

// ensureTable checks that the statistics table is usable and creates it when
// it is missing. It returns an error when the table can be neither used nor
// created; the caller then runs without MySQL.
func ensureTable(cfg FingerprintStoreConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	probe := "SELECT 1 FROM " + cfg.Table + " LIMIT 1"
	if _, err := cfg.DB.QueryContext(ctx, probe); err == nil {
		return nil
	}

	for _, stmt := range SchemaFor(cfg.Dialect, cfg.Table) {
		if _, err := cfg.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("creating %s: %w", cfg.Table, err)
		}
	}
	// CREATE can succeed while the table stays unreadable (rights, a race
	// with another instance); probe again.
	if _, err := cfg.DB.QueryContext(ctx, probe); err != nil {
		return fmt.Errorf("%s created but not readable: %w", cfg.Table, err)
	}
	return nil
}

// createTableSQL adapts the DDL to the configured table name, which may carry
// a schema prefix such as "ja4.bg_fingerprints".
func createTableSQL(table string) string {
	ddl := SchemaSQL
	if i := strings.Index(ddl, "\n--"); i > 0 {
		ddl = ddl[:i] // drop the trailing comments, they are not a statement
	}
	return strings.Replace(ddl,
		"CREATE TABLE IF NOT EXISTS bg_fingerprints",
		"CREATE TABLE IF NOT EXISTS "+table, 1)
}

func newFingerprintStore(cfg FingerprintStoreConfig, onErr func(error)) *fingerprintStore {
	if !cfg.Enabled || cfg.DB == nil {
		return nil
	}
	if cfg.Table == "" {
		cfg.Table = "bg_fingerprints"
	}
	if cfg.Dialect == "" {
		cfg.Dialect = detectDialect(cfg.DB)
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 500
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.SampleRate <= 0 {
		cfg.SampleRate = 1
	}
	// Without a usable table every batch would fail; disable statistics
	// instead.
	if err := ensureTable(cfg); err != nil {
		if onErr != nil {
			onErr(fmt.Errorf("botguard: fingerprint store disabled: %w", err))
		}
		return nil
	}

	s := &fingerprintStore{
		cfg:    cfg,
		onErr:  onErr,
		events: make(chan fpEvent, cfg.BufferSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		bad:    map[fpKey]struct{}{},
	}
	go s.run()
	if cfg.ReloadBadEvery > 0 {
		s.reloadBad()
		go s.reloadLoop()
	}
	return s
}

// push never blocks: on buffer overflow the event is dropped.
func (s *fingerprintStore) push(e fpEvent) {
	if s == nil || e.key.FP == "" {
		return
	}
	select {
	case s.events <- e:
	default:
		s.dropMu.Lock()
		s.dropped++
		s.dropMu.Unlock()
	}
}

// Dropped reports how many events were lost to overflow.
func (s *fingerprintStore) Dropped() uint64 {
	if s == nil {
		return 0
	}
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	return s.dropped
}

func (s *fingerprintStore) run() {
	defer close(s.done)
	agg := make(map[fpKey]*fpAgg)
	t := time.NewTicker(s.cfg.FlushInterval)
	defer t.Stop()

	for {
		select {
		case e := <-s.events:
			a, ok := agg[e.key]
			if !ok {
				a = &fpAgg{}
				agg[e.key] = a
			}
			if e.ua != "" {
				a.ua, a.family = e.ua, e.family
			}
			if e.asn != 0 {
				a.asn = e.asn
			}
			if e.cc != "" {
				a.cc = e.cc
			}
			if e.utype != "" {
				a.utype = e.utype
			}
			a.hits += e.hit
			a.challenged += e.challenged
			a.solved += e.solved
			a.failed += e.failed
			a.last = time.Now()
			if len(agg) >= s.cfg.MaxBatch {
				s.flush(agg)
				agg = make(map[fpKey]*fpAgg)
			}
		case <-t.C:
			if len(agg) > 0 {
				s.flush(agg)
				agg = make(map[fpKey]*fpAgg)
			}
		case <-s.stop:
			// drain the queue and flush what is left
			for {
				select {
				case e := <-s.events:
					a, ok := agg[e.key]
					if !ok {
						a = &fpAgg{}
						agg[e.key] = a
					}
					if e.ua != "" {
						a.ua, a.family = e.ua, e.family
					}
					a.hits += e.hit
					a.challenged += e.challenged
					a.solved += e.solved
					a.failed += e.failed
					a.last = time.Now()
				default:
					if len(agg) > 0 {
						s.flush(agg)
					}
					return
				}
			}
		}
	}
}

func (s *fingerprintStore) flush(agg map[fpKey]*fpAgg) {
	if len(agg) == 0 {
		return
	}
	var sb strings.Builder
	sb.WriteString("INSERT INTO ")
	sb.WriteString(s.cfg.Table)
	sb.WriteString(" (fp_kind,fingerprint,ua_hash,ua,ua_family,last_asn,last_cc,last_type," +
		"hits,challenged,solved,failed,first_seen,last_seen) VALUES ")

	args := make([]interface{}, 0, len(agg)*14)
	i := 0
	for k, a := range agg {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('(')
		for c := 0; c < 14; c++ {
			if c > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(s.cfg.Dialect.placeholder(i*14 + c + 1))
		}
		sb.WriteByte(')')
		ts := a.last
		if ts.IsZero() {
			ts = time.Now()
		}
		args = append(args, k.Kind, k.FP, k.UAHash, truncate(a.ua, 512), a.family,
			a.asn, truncate(a.cc, 2), truncate(a.utype, 32),
			a.hits, a.challenged, a.solved, a.failed, ts, ts)
		i++
	}
	sb.WriteString(s.cfg.Dialect.upsertClause())

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.WriteTimeout)
	defer cancel()
	if _, err := s.cfg.DB.ExecContext(ctx, sb.String(), args...); err != nil && s.onErr != nil {
		s.onErr(fmt.Errorf("botguard: writing fingerprints: %w", err))
	}
}

func (s *fingerprintStore) reloadLoop() {
	t := time.NewTicker(s.cfg.ReloadBadEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.reloadBad()
		case <-s.stop:
			return
		}
	}
}

func (s *fingerprintStore) reloadBad() {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.WriteTimeout)
	defer cancel()

	rows, err := s.cfg.DB.QueryContext(ctx,
		"SELECT fp_kind, fingerprint, ua_hash FROM "+s.cfg.Table+" WHERE verdict='bad'")
	if err != nil {
		if s.onErr != nil {
			s.onErr(fmt.Errorf("botguard: loading bad pairs: %w", err))
		}
		return
	}
	defer rows.Close()

	next := make(map[fpKey]struct{})
	for rows.Next() {
		var k fpKey
		if err := rows.Scan(&k.Kind, &k.FP, &k.UAHash); err != nil {
			continue
		}
		next[k] = struct{}{}
	}
	s.badMu.Lock()
	s.bad = next
	s.badMu.Unlock()
}

func (s *fingerprintStore) isBad(k fpKey) bool {
	if s == nil {
		return false
	}
	s.badMu.RLock()
	_, ok := s.bad[k]
	s.badMu.RUnlock()
	return ok
}

func (s *fingerprintStore) close() {
	if s == nil {
		return
	}
	close(s.stop)
	<-s.done
}

// uaFamily is a coarse browser family, for grouping fingerprints by browser.
func uaFamily(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case l == "":
		return "empty"
	case strings.Contains(l, "edg/"):
		return "edge"
	case strings.Contains(l, "opr/"), strings.Contains(l, "opera"):
		return "opera"
	case strings.Contains(l, "yabrowser"):
		return "yandex"
	case strings.Contains(l, "firefox/"):
		return "firefox"
	case strings.Contains(l, "chrome/"), strings.Contains(l, "chromium"):
		return "chrome"
	case strings.Contains(l, "safari/"):
		return "safari"
	case strings.Contains(l, "bot"), strings.Contains(l, "spider"), strings.Contains(l, "crawler"):
		return "bot"
	}
	return "other"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ═════════════════════════════ CHALLENGE ═════════════════════════════

type ChallengeConfig struct {
	// VerifyPath is the endpoint the page posts the PoW solution to.
	VerifyPath string
	// CaptchaPath is where the captcha answer goes (the third stage).
	CaptchaPath string
	// CheckboxPath is where the checkbox check result goes.
	CheckboxPath string
	// BaseDifficulty is the number of leading zero bits in the SHA-256.
	BaseDifficulty int
	// MaxDifficulty is the ceiling; above 22 old phones time out.
	MaxDifficulty int
	// DifficultyPerScore is the added difficulty per unit of score over the
	// threshold.
	DifficultyPerScore float64
	TokenTTL           time.Duration
	// StatusCode of the page. 503 does not hurt search results, 200 does.
	StatusCode int
	// RejectWebdriver rejects navigator.webdriver === true.
	RejectWebdriver bool
	Title           string
	BrandHTML       template.HTML
	// ContactHTML is the contact shown on the refusal page (403/429), e.g.
	// `<a href="mailto:abuse@example.com">abuse@example.com</a>`.
	// Empty hides the contact block.
	ContactHTML template.HTML
	// Template replaces the whole page. Fields: .Token .Difficulty
	// .VerifyPath .Title .BrandHTML
	Template *template.Template
}

func DefaultChallengeConfig() ChallengeConfig {
	return ChallengeConfig{
		VerifyPath:   "/__bg/verify",
		CaptchaPath:  "/__bg/captcha",
		CheckboxPath: "/__bg/checkbox",
		// d=15 is about 0.1 s on a desktop and up to a second on a weak
		// phone; d=17 is four times that. Below 14 only the "JS required"
		// barrier is left.
		BaseDifficulty:     15,
		MaxDifficulty:      17,
		DifficultyPerScore: 0.25,
		// Long enough for a slow device to finish the PoW before the token
		// expires, otherwise it reloads forever.
		TokenTTL:        180 * time.Second,
		StatusCode:      http.StatusServiceUnavailable,
		RejectWebdriver: true,
		Title:           "Checking your browser",
	}
}

type challengeToken struct {
	Nonce string `json:"n"`
	TS    int64  `json:"t"`
	Bind  string `json:"b"`
	Diff  int    `json:"d"`
	FPK   string `json:"k"` // fingerprint kind
	FP    string `json:"f"` // to record the outcome in the store
	UAH   string `json:"u"`
}

// effChallengeScore is the score that drives the difficulty and the stage
// escalation. An overflow on a shared dimension is the crowd's, not this
// visitor's, and does not raise either.
func (g *Guard) effChallengeScore(v Verdict) float64 {
	if strings.HasPrefix(v.Reason, "score:") &&
		g.isSharedDim(strings.TrimPrefix(v.Reason, "score:")) {
		return g.cfg.Thresholds.ChallengeAt
	}
	return v.Score
}

// isSharedDim reports whether the dimension's key covers many unrelated
// clients. Config.SharedScoreDims overrides the default set.
func (g *Guard) isSharedDim(dim string) bool {
	dims := g.cfg.SharedScoreDims
	if dims == nil {
		dims = []string{"fp@host", "fp", "asn_fp@host", "asn"}
	}
	for _, d := range dims {
		if d == dim {
			return true
		}
	}
	return false
}

// isHardReason reports whether the reason matches a Thresholds.HardReasons
// prefix.
func (g *Guard) isHardReason(reason string) bool {
	for _, hr := range g.cfg.Thresholds.HardReasons {
		if hr != "" && strings.HasPrefix(reason, hr) {
			return true
		}
	}
	return false
}

func (g *Guard) difficultyFor(score float64) int {
	c := g.cfg.Challenge
	d := c.BaseDifficulty
	if c.DifficultyPerScore > 0 && score > g.cfg.Thresholds.ChallengeAt {
		d += int((score - g.cfg.Thresholds.ChallengeAt) * c.DifficultyPerScore)
	}
	if d > c.MaxDifficulty {
		d = c.MaxDifficulty
	}
	if d < 1 {
		d = 1
	}
	return d
}

func (g *Guard) issueToken(s Signals, score float64) (string, int) {
	diff := g.difficultyFor(score)
	t := challengeToken{
		Nonce: randomNonce(), TS: g.cfg.now().UnixMilli(),
		Bind: g.bindValue(s), Diff: diff,
		FPK: s.FPKind, FP: s.FPrint, UAH: s.UAHash,
	}
	body, _ := json.Marshal(t)
	enc := base64.RawURLEncoding.EncodeToString(body)
	return enc + "." + g.sign(enc), diff
}

func (g *Guard) parseToken(tok string) (challengeToken, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return challengeToken{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(g.signBytes(parts[0]), sig) {
		return challengeToken{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return challengeToken{}, false
	}
	var t challengeToken
	if json.Unmarshal(raw, &t) != nil {
		return challengeToken{}, false
	}
	return t, true
}

// checkPoW is the same algorithm the browser runs: SHA-256(token:nonce) must
// start with diff zero bits.
func checkPoW(token, nonce string, diff int) bool {
	sum := sha256.Sum256([]byte(token + ":" + nonce))
	zeros := 0
	for _, b := range sum {
		if b == 0 {
			zeros += 8
			continue
		}
		zeros += bits.LeadingZeros8(b)
		break
	}
	return zeros >= diff
}

type verifyRequest struct {
	Token string `json:"token"`
	Nonce string `json:"nonce"`
	Env   struct {
		Webdriver bool   `json:"wd"`
		TZ        string `json:"tz"`
		Cores     int    `json:"hc"`
		Width     int    `json:"w"`
		Height    int    `json:"h"`
	} `json:"env"`
}

const defaultChallengeHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>
 body{font:16px/1.5 system-ui,-apple-system,sans-serif;display:grid;place-items:center;
      min-height:100vh;margin:0;color:#2c2c2c;background:#fafafa}
 .box{text-align:center;max-width:420px;padding:32px}
 .sp{width:34px;height:34px;margin:0 auto 20px;border:3px solid #e0e0e0;
     border-top-color:#767676;border-radius:50%;animation:s .8s linear infinite}
 @keyframes s{to{transform:rotate(360deg)}}
 small{color:#888;display:block;margin-top:8px}
</style></head>
<body><div class="box">
 {{.BrandHTML}}
 <div class="sp" id="sp"></div>
 <p id="msg">Checking your browser…</p>
 <small>This will take a few seconds and happens automatically.</small>
 <noscript><p>JavaScript must be enabled to continue.</p></noscript>
</div>
<script>
(async () => {
  const token = {{.Token}}, difficulty = {{.Difficulty}}, url = {{.VerifyPath}};
  const msg = document.getElementById('msg'), enc = new TextEncoder();
  if (!self.crypto || !crypto.subtle) {
    msg.textContent = 'Your browser does not support this check. Please update it.';
    return;
  }
  const zeros = (buf) => {
    let n = 0;
    for (const b of new Uint8Array(buf)) {
      if (b === 0) { n += 8; continue; }
      n += Math.clz32(b) - 24; break;
    }
    return n;
  };
  let nonce = 0;
  for (;;) {
    const d = await crypto.subtle.digest('SHA-256', enc.encode(token + ':' + nonce));
    if (zeros(d) >= difficulty) break;
    nonce++;
    if (nonce % 2000 === 0) await new Promise(r => setTimeout(r));
  }
  try {
    const res = await fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({token, nonce: String(nonce), env: {
        wd: navigator.webdriver === true,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        hc: navigator.hardwareConcurrency || 0,
        w: screen.width, h: screen.height
      }})
    });
    if (res.ok) {
      try { sessionStorage.removeItem('bg_retried'); } catch (e) {}
      location.reload();
      return;
    }
  } catch (e) {}
  // No manual reload prompt: usually the cause is an expired token (a slow
  // device spent longer on the PoW than TokenTTL) and a new page issues a fresh
  // one. One automatic retry, then a link, so we do not loop forever when the
  // token is not the problem.
  if (!sessionStorage.getItem('bg_retried')) {
    try { sessionStorage.setItem('bg_retried', '1'); } catch (e) {}
    msg.textContent = 'Retrying…';
    setTimeout(function(){ location.reload(); }, 900);
    return;
  }
  document.getElementById('sp').style.display = 'none';
  msg.innerHTML = 'Verification failed. <a href="" onclick="' +
    'sessionStorage.removeItem(\'bg_retried\');location.reload();return false;">Try again</a>';
})();
</script></body></html>`

type challengePageData struct {
	Token      string
	Difficulty int
	VerifyPath string
	Title      string
	BrandHTML  template.HTML
}

// isSecureReq reports whether the connection is HTTPS, including behind a
// terminating proxy where echo derives the scheme from forwarding headers.
func isSecureReq(r *http.Request, scheme string) bool {
	return r.TLS != nil || scheme == "https"
}

// origRefCookie carries the visitor's original Referer across a challenge.
// The challenge page leaves with location.reload(), and a reload sends the
// page itself as the referrer, so the real source would be lost.
const origRefCookie = "bg_ref"

// RefererMode selects how the recovered traffic source reaches client-side
// analytics. The Referer header is restored in every mode.
type RefererMode string

const (
	// RefererHeaderOnly restores the header and touches nothing else.
	RefererHeaderOnly RefererMode = "off"
	// RefererInject also injects a document.referrer shim into the first HTML
	// page after a pass. The default.
	RefererInject RefererMode = "inject"
	// RefererQueryParam instead redirects the first request after a pass to
	// the same URL with the source appended as a query parameter
	// (Config.RefererParam).
	RefererQueryParam RefererMode = "param"
	// RefererBoth does both.
	RefererBoth RefererMode = "both"
)

// origRefEmpty marks a stashed empty referrer, so a direct visit stays
// direct rather than becoming a self-referral.
const origRefEmpty = "-"

// TrackingHeader carries the tracking id on every response, the newly
// issued one included: the request cookie is empty on first contact, so
// without the header the first response could not be linked to the visitor.
const TrackingHeader = "X-BG-Trk"

// ensureTrackingCookie issues a random per-browser id to visitors without
// one and mirrors it into TrackingHeader.
func (g *Guard) ensureTrackingCookie(w http.ResponseWriter, r *http.Request, secure bool) {
	name := g.cfg.TrackingCookie
	if name == "" {
		return
	}
	if c, err := r.Cookie(name); err == nil && c.Value != "" {
		w.Header().Set(TrackingHeader, c.Value)
		return // already tagged
	}
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return
	}
	id := base64.RawURLEncoding.EncodeToString(buf)
	w.Header().Set(TrackingHeader, id)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    id,
		Path:     "/",
		MaxAge:   int((30 * 24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// saveOrigReferer stashes the referrer as it arrived, absent included. An
// existing stash is kept: later challenge rounds carry our own page.
func (g *Guard) saveOrigReferer(w http.ResponseWriter, r *http.Request, secure bool) {
	if _, err := r.Cookie(origRefCookie); err == nil {
		return
	}
	v := origRefEmpty
	if ref := r.Referer(); ref != "" {
		v = url.QueryEscape(ref)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     origRefCookie,
		Value:    v,
		Path:     "/",
		MaxAge:   int(g.cfg.Challenge.TokenTTL / time.Second),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// restoreOrigReferer puts the stashed source back on the request before it
// reaches the application, then clears the cookie so it applies once.
func (g *Guard) restoreOrigReferer(w http.ResponseWriter, r *http.Request, secure bool) (string, bool) {
	c, err := r.Cookie(origRefCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	http.SetCookie(w, &http.Cookie{
		Name: origRefCookie, Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode,
	})
	if c.Value == origRefEmpty {
		// A direct visit stays direct: drop the reload's self-referral.
		r.Header.Del("Referer")
		return "", true
	}
	ref := validRefererValue(c.Value)
	if ref == "" {
		return "", false
	}
	r.Header.Set("Referer", ref)
	return ref, true
}

// validRefererValue decodes a stashed cookie value and accepts only an
// absolute http(s) URL: the cookie is visitor-controlled.
func validRefererValue(v string) string {
	ref, err := url.QueryUnescape(v)
	if err != nil || ref == "" {
		return ""
	}
	u, perr := url.Parse(ref)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return ref
}

// refererParamName returns the configured query parameter for param mode.
func (g *Guard) refererParamName() string {
	if g.cfg.RefererParam != "" {
		return g.cfg.RefererParam
	}
	return "bg_ref"
}

// refShim is the script that makes document.referrer report the original
// traffic source on the first page after a challenge. Injected right after
// <head> so it runs before any analytics script.
func refShim(ref string) []byte {
	b, _ := json.Marshal(ref) // a safe JS string literal
	js := strings.ReplaceAll(string(b), "</", "<\\/")
	return []byte("<script>try{Object.defineProperty(document,'referrer',{get:function(){return " + js + "}})}catch(e){}</script>")
}

// refInjector rewrites the first HTML chunk of the response to carry the shim.
// Anything that is not a plain 200 HTML page passes through untouched.
type refInjector struct {
	rw      http.ResponseWriter
	shim    []byte
	state   int  // 0 undecided, 1 inject pending, 2 passthrough
	pending bool // a 200 was announced but not yet forwarded
}

func (i *refInjector) Header() http.Header { return i.rw.Header() }

// WriteHeader holds a 200 back until the first Write: some frameworks set
// the status before Content-Type. Other codes go straight through.
func (i *refInjector) WriteHeader(code int) {
	if i.state != 0 {
		i.rw.WriteHeader(code)
		return
	}
	if code != http.StatusOK {
		i.state = 2
		i.rw.WriteHeader(code)
		return
	}
	i.pending = true
}

func (i *refInjector) decide() {
	h := i.rw.Header()
	if strings.HasPrefix(h.Get("Content-Type"), "text/html") && h.Get("Content-Encoding") == "" {
		i.state = 1
		h.Del("Content-Length") // the body is about to grow
	} else {
		i.state = 2
	}
	i.pending = false
	i.rw.WriteHeader(http.StatusOK)
}

func (i *refInjector) Write(b []byte) (int, error) {
	if i.state == 0 {
		i.decide()
	}
	if i.state == 1 {
		i.state = 2
		if at := headInsertPoint(b); at >= 0 {
			out := make([]byte, 0, len(b)+len(i.shim))
			out = append(out, b[:at]...)
			out = append(out, i.shim...)
			out = append(out, b[at:]...)
			if _, err := i.rw.Write(out); err != nil {
				return 0, err
			}
			return len(b), nil
		}
		// No <head> in the first chunk: leave the page alone.
	}
	return i.rw.Write(b)
}

func (i *refInjector) Flush() {
	if i.state == 0 && i.pending {
		i.decide()
	}
	if f, ok := i.rw.(http.Flusher); ok {
		f.Flush()
	}
}

// headInsertPoint returns the offset just past the opening <head> tag, or -1.
func headInsertPoint(b []byte) int {
	low := bytes.ToLower(b)
	at := bytes.Index(low, []byte("<head"))
	if at < 0 {
		return -1
	}
	end := bytes.IndexByte(b[at:], '>')
	if end < 0 {
		return -1
	}
	return at + end + 1
}

func (g *Guard) renderChallenge(w http.ResponseWriter, s Signals, score float64) {
	token, diff := g.issueToken(s, score)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(g.cfg.Challenge.StatusCode)
	_ = g.tmpl.Execute(w, challengePageData{
		Token: token, Difficulty: diff, VerifyPath: g.cfg.Challenge.VerifyPath,
		Title: g.cfg.Challenge.Title, BrandHTML: g.cfg.Challenge.BrandHTML,
	})
	g.recordFP(s, fpEvent{challenged: 1})
}

// deniedHTML is the refusal page. Ref is a short code that locates the
// request in the logs.
const deniedHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>
 body{font:16px/1.6 system-ui,-apple-system,sans-serif;display:grid;place-items:center;
      min-height:100vh;margin:0;color:#2c2c2c;background:#fafafa}
 .box{text-align:center;max-width:480px;padding:32px}
 h1{font-size:20px;margin:0 0 12px}
 p{margin:0 0 12px;color:#555}
 code{background:#eee;padding:2px 6px;border-radius:4px;font-size:13px}
 a{color:#0066cc}
</style></head>
<body><div class="box">
 <h1>{{.Heading}}</h1>
 <p>{{.Message}}</p>
 {{if .Contact}}<p>If you believe this is a mistake, contact us: {{.Contact}}</p>{{end}}
 <p><small>Reference: <code>{{.Ref}}</code></small></p>
</div></body></html>`

type deniedPageData struct {
	Title, Heading, Message, Ref string
	Contact                      template.HTML
}

// renderDenied serves a human-readable page instead of a bare 403/429.
func (g *Guard) renderDenied(w http.ResponseWriter, status int, v Verdict) {
	heading := "Access denied"
	msg := "Your request was blocked by our automated protection system."
	if status == http.StatusTooManyRequests {
		heading = "Too many requests"
		msg = "You are sending requests too quickly. Please wait a minute and try again."
	}
	ref := shortHash(v.Signals.IPStr + "|" + v.Reason)[:8] // locates the request in the logs

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = g.deniedTmpl.Execute(w, deniedPageData{
		Title:   heading,
		Heading: heading,
		Message: msg,
		Ref:     ref,
		Contact: g.cfg.Challenge.ContactHTML,
	})
}

// ═══════════════════════════ CLEARANCE (COOKIE) ═══════════════════════════

const ClearanceCookie = "bg_clearance"

type clearancePayload struct {
	Exp  int64  `json:"e"`
	Bind string `json:"b"`
	UA   string `json:"u"`
}

// bindValue is the network binding of tokens and clearances. Always empty:
// binding to a /24 or /16 fails on carriers, CGNAT and proxy pools, where
// the address changes between the challenge and the answer. Tokens rely on
// the HMAC, single use and the UA hash.
func (g *Guard) bindValue(s Signals) string {
	return ""
}

func (g *Guard) issueClearance(w http.ResponseWriter, s Signals, secure bool) {
	p := clearancePayload{
		Exp:  g.cfg.now().Add(g.cfg.ClearanceTTL).Unix(),
		Bind: g.bindValue(s),
		UA:   s.UAHash,
	}
	body, _ := json.Marshal(p)
	enc := base64.RawURLEncoding.EncodeToString(body)
	http.SetCookie(w, &http.Cookie{
		Name: ClearanceCookie, Value: enc + "." + g.sign(enc), Path: "/",
		MaxAge: int(g.cfg.ClearanceTTL.Seconds()), HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func (g *Guard) hasClearance(r *http.Request, s Signals) bool {
	ck, err := r.Cookie(ClearanceCookie)
	if err != nil {
		return false
	}
	parts := strings.SplitN(ck.Value, ".", 2)
	if len(parts) != 2 || !hmac.Equal([]byte(g.sign(parts[0])), []byte(parts[1])) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var p clearancePayload
	if json.Unmarshal(raw, &p) != nil {
		return false
	}
	return p.Exp > g.cfg.now().Unix() && p.Bind == g.bindValue(s) && p.UA == s.UAHash
}

// ClearCookie revokes the clearance.
func ClearCookie() *http.Cookie {
	return &http.Cookie{Name: ClearanceCookie, Path: "/", MaxAge: -1}
}

func (g *Guard) sign(data string) string {
	return base64.RawURLEncoding.EncodeToString(g.signBytes(data))
}

func (g *Guard) signBytes(data string) []byte {
	m := hmac.New(sha256.New, g.cfg.Secret)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func randomNonce() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// ══════════════════════════ ENGINE AND VERDICT ══════════════════════════

type Decision int

const (
	Allow Decision = iota
	Challenge
	Block
	TooMany
)

func (d Decision) String() string {
	switch d {
	case Challenge:
		return "challenge"
	case Block:
		return "block"
	case TooMany:
		return "too_many"
	}
	return "allow"
}

type Verdict struct {
	Decision     Decision
	Score        float64
	Reason       string
	Cleared      bool
	Enforced     bool // false in ModeMonitor: computed but not applied
	Signals      Signals
	Rates        map[string]float64
	Limits       map[string]float64
	Behavior     BehaviorStats
	BehaviorHits []BehaviorHit
}

// Explain renders the verdict as a log line.
func (v Verdict) Explain() string {
	p := []string{fmt.Sprintf("decision=%s score=%.2f reason=%s ua=%s fp=%s",
		v.Decision, v.Score, v.Reason, v.Signals.UAKind, v.Signals.FPKind)}
	if v.Signals.ASN != 0 {
		p = append(p, fmt.Sprintf("asn=%d/%s/%s", v.Signals.ASN,
			orDash(v.Signals.UsageType), orDash(v.Signals.ConnType)))
	}
	if v.Signals.Country != "" {
		p = append(p, "cc="+v.Signals.Country)
	}
	names := make([]string, 0, len(v.Rates))
	for n := range v.Rates {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p = append(p, fmt.Sprintf("%s=%.0f/%.0f", n, v.Rates[n], v.Limits[n]))
	}
	for _, h := range v.BehaviorHits {
		p = append(p, "behav:"+h.Rule)
	}
	return strings.Join(p, " ")
}

type Guard struct {
	cfg          Config
	store        *store
	fps          *fingerprintStore
	tmpl         *template.Template
	deniedTmpl   *template.Template
	captchaTmpl  *template.Template
	log          Logger
	checkboxTmpl *template.Template
	blockASN     map[uint32]bool
	challASN     map[uint32]bool
	trustedASN   map[uint32]bool
	sampleN      uint64
	sampleMu     sync.Mutex
}

func New(rdb redis.UniversalClient, cfg Config) (*Guard, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	g := &Guard{
		cfg: cfg,
		log: cfg.Logger,
		store: &store{
			rdb: rdb, prefix: cfg.KeyPrefix,
			rate:  redis.NewScript(rateLua),
			behav: redis.NewScript(behaviorLua),
		},
		blockASN:   toSet(cfg.Network.BlockASN),
		challASN:   toSet(cfg.Network.AlwaysChallengeASN),
		trustedASN: toSet(cfg.Network.TrustedASN),
	}
	tmpl := cfg.Challenge.Template
	if tmpl == nil {
		var err error
		if tmpl, err = template.New("challenge").Parse(defaultChallengeHTML); err != nil {
			return nil, err
		}
	}
	g.tmpl = tmpl
	dt, err := template.New("denied").Parse(deniedHTML)
	if err != nil {
		return nil, err
	}
	g.deniedTmpl = dt
	ct, err := template.New("captcha").Parse(defaultCaptchaHTML)
	if err != nil {
		return nil, err
	}
	g.captchaTmpl = ct
	bt, err := template.New("checkbox").Parse(defaultCheckboxHTML)
	if err != nil {
		return nil, err
	}
	g.checkboxTmpl = bt
	if g.log == nil {
		g.log = nopLogger{}
	}
	g.fps = newFingerprintStore(cfg.Store, cfg.OnError)
	return g, nil
}

// Close stops the background tasks and flushes the remaining stats.
func (g *Guard) Close() { g.fps.close() }

// DroppedFingerprintEvents reports how many observations were lost to buffer
// overflow.
func (g *Guard) DroppedFingerprintEvents() uint64 { return g.fps.Dropped() }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func toSet(list []uint32) map[uint32]bool {
	m := make(map[uint32]bool, len(list))
	for _, v := range list {
		m[v] = true
	}
	return m
}

// Evaluate makes the decision. Its only side effect is incrementing the
// counters.
func (g *Guard) Evaluate(ctx context.Context, r *http.Request) Verdict {
	s := g.extract(r)
	v := Verdict{Signals: s, Cleared: g.hasClearance(r, s)}
	defer func() { g.recordFP(s, fpEvent{hit: 1}) }()

	// 1. Blacklisted ASN.
	if s.ASN != 0 && g.blockASN[s.ASN] {
		v.Decision, v.Reason, v.Score = Block, "blocked_asn", 99
		return v
	}

	// 2. The failed-challenge budget is used up.
	if g.store.rdb != nil {
		if n, err := g.store.rdb.Get(ctx, g.cfg.KeyPrefix+"cf:"+s.IPStr).Int64(); err == nil &&
			n >= g.cfg.Thresholds.ChallengeFailsBeforeBlock {
			v.Decision, v.Reason, v.Score = Block, "challenge_failures", 99
			return v
		}
	}

	// 3. Declared bots. They pass unless they come from outside their own
	//    ASNs or the config restricts them. Known bots are never challenged:
	//    they do not run JS.
	if s.UAKind == UAKnownBot {
		return g.evaluateKnownBot(ctx, s, v)
	}
	if s.UAKind == UABadBot {
		v.Decision, v.Reason, v.Score = Block, "seo_blacklist", 99
		return v
	}
	if s.UAKind == UAToolAgent {
		// A challenge rather than a block: monitoring and previews look like
		// tools too. A script drops out on its own, a browser passes.
		v.Decision, v.Reason = Challenge, "tool_agent"
		if v.Score < g.cfg.Thresholds.ChallengeAt {
			v.Score = g.cfg.Thresholds.ChallengeAt
		}
		return v
	}
	if s.UAKind == UAAIBot {
		v.Decision, v.Reason = Allow, "ai_crawler_allow"
		return v
	}
	if s.UAKind == UAUnknownBot {
		// Undescribed bots pass; the stats page lists them for sorting.
		v.Decision, v.Reason = Allow, "unknown_bot_allow"
		return v
	}
	// UABehavioral (previews without an ASN, Headless Chrome) takes the
	// common path below.

	// 4. Rates.
	rates, limits, err := g.measure(ctx, s, true)
	if err != nil {
		if g.cfg.OnError != nil {
			g.cfg.OnError(err)
		}
		if g.cfg.FailOpen {
			v.Decision, v.Reason = Allow, "store_error_fail_open"
		} else {
			v.Decision, v.Reason = TooMany, "store_error_fail_closed"
		}
		return v
	}
	v.Rates, v.Limits = rates, limits

	mult := 1.0
	if v.Cleared {
		mult = g.cfg.ClearanceMult
	}
	worst := ""
	for name, rate := range rates {
		lim := limits[name] * mult
		if lim <= 0 {
			continue
		}
		if x := rate / lim; x > v.Score {
			v.Score, worst = x, name
		}
	}

	// 5. Behavior. The weights add to the rate score.
	if g.cfg.Behavior.Enabled {
		b, err := g.store.behavior(ctx, s.IPStr+"|"+s.UAHash, s,
			g.cfg.Behavior.TTL, g.cfg.Behavior.MaxGap, g.cfg.now())
		if err == nil {
			v.Behavior = b
			bs, hits := g.behaviorScore(b)
			v.Score += bs
			v.BehaviorHits = hits
			if bs > 0 && worst == "" {
				worst = hits[0].Rule
			}
		} else if g.cfg.OnError != nil {
			g.cfg.OnError(err)
		}
	}

	// 6. Empty User-Agent.
	if s.UAKind == UAEmpty {
		v.Score += g.cfg.Thresholds.EmptyUAWeight
		if worst == "" {
			worst = "empty_ua"
		}
	}

	// 7. A fingerprint/UA pair marked bad in the store.
	if g.fps.isBad(fpKey{Kind: s.FPKind, FP: s.FPrint, UAHash: s.UAHash}) {
		v.Score += g.cfg.Thresholds.MismatchWeight
		if worst == "" {
			worst = "known_bad_fingerprint"
		}
	}

	// 8. ASNs for which the challenge is forced on.
	if s.ASN != 0 && g.challASN[s.ASN] && !v.Cleared {
		v.Decision, v.Reason = Challenge, "asn_always_challenge"
		if v.Score < g.cfg.Thresholds.ChallengeAt {
			v.Score = g.cfg.Thresholds.ChallengeAt
		}
		return v
	}

	// 9. A browser UA from a datacenter: a bot or a person on a VPN. The
	//    challenge tells them apart; blocking would hit VPN users.
	if g.cfg.Network.ChallengeHostingBrowsers && g.isHosting(s) &&
		s.UAKind == UABrowser && !v.Cleared {
		v.Decision, v.Reason = Challenge, "hosting_browser"
		if v.Score < g.cfg.Thresholds.ChallengeAt {
			v.Score = g.cfg.Thresholds.ChallengeAt
		}
		return v
	}

	// 10. Thresholds. A shared dimension (fingerprint, ASN) is also the key
	// of every genuine client behind it, so it never blocks or revokes a
	// clearance on its own; the challenge separates them.
	t := g.cfg.Thresholds
	shared := g.isSharedDim(worst)
	switch {
	case v.Score >= t.BlockAt && !shared:
		v.Decision, v.Reason = Block, "score:"+worst
	case !v.Cleared && v.Score >= t.ChallengeAt:
		v.Decision, v.Reason = Challenge, "score:"+worst
	case v.Cleared && !shared && v.Score >= t.BlockAt*t.ClearedAbuseRatio:
		v.Decision, v.Reason = Challenge, "cleared_abuse:"+worst
	default:
		v.Decision, v.Reason = Allow, "ok"
	}
	return v
}

func (g *Guard) evaluateKnownBot(ctx context.Context, s Signals, v Verdict) Verdict {
	kb := s.Bot

	if len(kb.ASNs) > 0 && s.ASN != 0 {
		ok := false
		for _, a := range kb.ASNs {
			if a == s.ASN {
				ok = true
				break
			}
		}
		if !ok {
			// ASN mismatch: an impostor. Allow is upgraded to a challenge so
			// an incomplete ASN list does not let one straight through, while
			// a genuine crawler from an unlisted network is not cut off.
			act := kb.OnASNMismatch
			if act == ActionAllow {
				act = ActionChallenge
			}
			v.Decision, v.Reason = actionToDecision(act), "fake_bot:"+kb.Name
			if v.Score < g.cfg.Thresholds.ChallengeAt {
				v.Score = g.cfg.Thresholds.ChallengeAt
			}
			return v
		}
	}
	// No ASN in the header: nothing to check, the bot passes.

	if kb.Limit > 0 {
		rates, limits, err := g.measure(ctx, s, true)
		if err != nil && g.cfg.OnError != nil {
			g.cfg.OnError(err)
		}
		if err == nil {
			v.Rates, v.Limits = rates, limits
			if rates["ip"] > kb.Limit {
				v.Decision, v.Reason = TooMany, "bot_flood:"+kb.Name
				return v
			}
		}
	}

	switch kb.OnMatch {
	case ActionBlock:
		v.Decision, v.Reason = Block, "bot_denied:"+kb.Name
	case ActionRateLimit:
		v.Decision, v.Reason = TooMany, "bot_ratelimited:"+kb.Name
	case ActionChallenge:
		v.Decision, v.Reason = Challenge, "bot_challenged:"+kb.Name
	default:
		v.Decision, v.Reason = Allow, "bot_ok:"+kb.Name
	}
	return v
}

func (g *Guard) evaluateToolAgent(ctx context.Context, s Signals, v Verdict) Verdict {
	if g.cfg.Bots.UnknownBotLimit > 0 {
		rates, limits, err := g.measure(ctx, s, true)
		if err == nil {
			v.Rates, v.Limits = rates, limits
			if rates["ip"] > g.cfg.Bots.UnknownBotLimit {
				v.Decision, v.Reason = TooMany, "tool_flood"
				return v
			}
		}
	}
	switch g.cfg.Bots.UnknownBots {
	case ActionBlock:
		v.Decision, v.Reason = Block, "tool_denied"
	case ActionRateLimit:
		v.Decision, v.Reason = TooMany, "tool_ratelimited"
	case ActionChallenge:
		// Rarely useful: such a client will not run JS.
		v.Decision, v.Reason = Challenge, "tool_challenged"
	default:
		v.Decision, v.Reason = Allow, "tool_ok"
	}
	return v
}

func actionToDecision(a Action) Decision {
	switch a {
	case ActionChallenge:
		return Challenge
	case ActionRateLimit:
		return TooMany
	case ActionBlock:
		return Block
	}
	return Allow
}

func (g *Guard) measure(ctx context.Context, s Signals, incr bool) (map[string]float64, map[string]float64, error) {
	dims := g.activeDimensions(s)
	rates, err := g.store.rates(ctx, dims, s, g.cfg.Window, g.cfg.now(), incr)
	if err != nil {
		return nil, nil, err
	}
	limits := make(map[string]float64, len(dims))
	for _, d := range dims {
		limits[d.Name] = d.Limit * g.limitFactor(d, s)
	}
	return rates, limits, nil
}

// recordFP queues an observation for the store, honoring SampleRate.
func (g *Guard) recordFP(s Signals, e fpEvent) {
	if g.fps == nil || s.FPrint == "" {
		return
	}
	if g.cfg.Store.SampleRate < 1 && !g.sample() {
		return
	}
	e.key = fpKey{Kind: s.FPKind, FP: s.FPrint, UAHash: s.UAHash}
	e.ua = s.UA
	e.family = uaFamily(s.UA)
	e.asn = s.ASN
	e.cc = s.Country
	e.utype = firstNonEmpty(s.UsageType, s.ConnType)
	g.fps.push(e)
}

// sample thins deterministically, every 1/SampleRate-th request.
func (g *Guard) sample() bool {
	step := uint64(1 / g.cfg.Store.SampleRate)
	if step < 1 {
		step = 1
	}
	g.sampleMu.Lock()
	g.sampleN++
	n := g.sampleN
	g.sampleMu.Unlock()
	return n%step == 0
}

func (g *Guard) noteChallengeFail(ctx context.Context, s Signals) {
	if g.store.rdb == nil {
		return
	}
	k := g.cfg.KeyPrefix + "cf:" + s.IPStr
	pipe := g.store.rdb.TxPipeline()
	pipe.Incr(ctx, k)
	pipe.Expire(ctx, k, 15*time.Minute)
	_, _ = pipe.Exec(ctx)
}

// markTokenUsed guards against reusing a solved challenge.
func (g *Guard) markTokenUsed(ctx context.Context, nonce string) bool {
	if g.store.rdb == nil {
		return g.cfg.FailOpen
	}
	ok, err := g.store.rdb.SetNX(ctx, g.cfg.KeyPrefix+"used:"+nonce, 1,
		g.cfg.Challenge.TokenTTL+time.Minute).Result()
	if err != nil {
		return g.cfg.FailOpen
	}
	return ok
}

// ═══════════════════════════ MIDDLEWARE (ECHO) ═══════════════════════════

func (g *Guard) shouldSkip(r *http.Request) bool {
	p := r.URL.Path
	if p == g.cfg.Challenge.VerifyPath {
		return true
	}
	for _, pref := range g.cfg.SkipPaths {
		if strings.HasPrefix(p, pref) {
			return true
		}
	}
	return g.cfg.SkipFunc != nil && g.cfg.SkipFunc(r)
}

func isAPIRequest(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" && m != "navigate" {
		return true
	}
	accept := r.Header.Get("Accept")
	return accept != "" &&
		!strings.Contains(accept, "text/html") &&
		!strings.Contains(accept, "*/*")
}
