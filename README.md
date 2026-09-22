# botguard

Adaptive bot protection for Go web servers. Tracks request rates across
several dimensions, classifies clients by User-Agent and ASN, then decides
whether to pass, challenge or block. Proof-of-work and checkbox challenges
let people through while botnets driving real browsers through residential
proxies get nothing but the challenge page — measured on live traffic:
165k botnet IPs solved 1 challenge out of 140k.

The core is plain `net/http`, so it works with the standard mux, chi,
gorilla and anything else built on `http.Handler`. Echo, Gin and Fiber have
adapters in their own modules, so a project pulls in only the framework it
uses.

```bash
go get github.com/hellmany/botguard           # core, net/http
go get github.com/hellmany/botguard/echo      # Echo v4 adapter
go get github.com/hellmany/botguard/gin       # Gin adapter
go get github.com/hellmany/botguard/fiber     # Fiber v2 adapter
```

## Requirements

- **Redis** — counters and challenge state. Required.
- **MySQL, PostgreSQL or SQLite** — fingerprint/User-Agent pair collection.
  Optional; the dialect is detected from the driver.
- **Frontend headers** — IP, JA4, ASN, network type. No mmdb lookups or
  runtime DNS. JA3/JA4 come from
  [nginx-ssl-fingerprint](https://github.com/phuslu/nginx-ssl-fingerprint)
  (`$http_ssl_ja4`, `$http_ssl_ja3`); without them the guard falls back to
  an HTTP-header fingerprint.
- **No caching of `/__bg/`** — a caching proxy in front of the guard must not
  cache challenge pages or responses that set a clearance cookie. See
  [Frontend requirements](#frontend-requirements).

## Setup

```go
p := botguard.DefaultParams()
p.Redis   = redisClient          // redis.UniversalClient
p.DB      = sqlDB                // *sql.DB, may be nil
p.Logger  = myLogger             // see "Logging"
p.LogPath = "/var/log/bg.log"    // same file your Logger writes to
p.Secret  = os.Getenv("BG_SECRET")
p.Enforce = false                // always start in monitor mode

botguard.InitStats(p)
g, err := botguard.New(p.Redis, botguard.NewConfig(p))
if err != nil {
    return err
}
```

Then wire it into your server — pick your framework:

### net/http, chi, gorilla — anything http.Handler

```go
mux := http.NewServeMux()
g.RegisterMux(mux)               // /__bg/* endpoints: verify, test pages, stats
mux.Handle("/", app)
http.ListenAndServe(":8080", g.HTTPMiddleware(mux))
```

With chi or gorilla the middleware is `r.Use(g.HTTPMiddleware)` and the
endpoints come from `g.Routes()`:

```go
for _, rt := range g.Routes() {
    r.Method(rt.Method, rt.Path, rt.Handler)   // chi
}
```

The verdict for the current request is `botguard.VerdictFromRequest(r)`.

### Echo v4

```go
import bgecho "github.com/hellmany/botguard/echo"

bgecho.Register(g, e)            // middleware + every /__bg/* endpoint
v, ok := bgecho.VerdictFrom(c)   // inside a handler
```

### Gin

```go
import bggin "github.com/hellmany/botguard/gin"

bggin.Register(g, r)             // r is *gin.Engine or a group
v, ok := bggin.VerdictFrom(c)
```

### Fiber v2

```go
import bgfiber "github.com/hellmany/botguard/fiber"

bgfiber.Register(g, app)         // via fiber's net/http adaptor
```

Every adapter is a thin wrapper over `HTTPMiddleware` and `Routes()`, so a
framework that is not listed needs about twenty lines — see `gin/gin.go`
for the pattern, including how to keep the framework's response-writer
bookkeeping intact when the core wraps the writer.

---

## Parameters (`botguard.Params`)

### Required

| Parameter | Purpose |
|---|---|
| `Redis` | rate counters and challenge state. Without it the guard fails open and passes everyone |
| `Secret` | HMAC key for tokens and cookies. At least 16 bytes. Changing it invalidates all issued clearances |
| `LogPath` | file the stats page reads verdicts from. Must match where your `Logger` writes |

### Mode

| Parameter | Default | Purpose |
|---|---|---|
| `Disabled` | `false` | switch the guard off entirely: no counters, no Redis, no statistics, no endpoints, not even monitoring. The middleware becomes a pass-through. Wins over `Enforce`. For turning it off without removing the wiring — during an incident, on a staging box |
| `Enforce` | `true` | `false` counts and logs without touching anyone. **Start here**: a week of monitoring reveals who the system would have hit by mistake |
| `LogAllowed` | `false` | also log visitors that pass. Off by default: an allow is the common case and the log grows by tens of gigabytes. Turn it on to see who holds a clearance — a passing visitor is otherwise absent from the log, which makes a working clearance look broken |
| `RefererMode` | `"inject"` | how the recovered traffic source reaches client-side analytics: `"inject"` shims `document.referrer` in the first HTML page after a pass, `"param"` redirects once adding the source as a query parameter, `"both"` does both, `"off"` restores only the `Referer` header. See [Referrer preservation](#referrer-preservation) |
| `RefererParam` | `"bg_ref"` | query parameter name for `RefererMode: "param"` |
| `BlockAI` | `false` | block AI crawlers (GPTBot, ClaudeBot, Bytespider). A product decision: allowing them may get you cited in assistant answers, blocking saves bandwidth |

### Scoring thresholds

Score is `rate / limit` per dimension, the maximum wins. Behavioural rules
add on top.

| Parameter | Default | Purpose |
|---|---|---|
| `ChallengeAt` | `1.0` | over the limit — serve proof-of-work (~0.1 s, unnoticeable) |
| `CheckboxAt` | `6.0` | six times over — checkbox with environment checks |
| `CaptchaAt` | `0` (off) | character-entry captcha. Zero disables the stage |
| `BlockAt` | `20.0` | twenty times over — 403. Deliberately high: a single IP may be an office or a mobile carrier |
| `TrackingCookie` | empty (off) | name of a cookie set for every visitor on first contact — the challenge 503 included — with a random per-browser id. The guard itself never reads it; its purpose is the frontend log: the id is also mirrored into the `X-BG-Trk` response header on every backend response, the `/__bg/*` verify endpoints included, so log `bg:$upstream_http_x_bg_trk` in nginx — unlike the request cookie, the header is present already on the very first 503, so even a visitor who left right after the challenge is linkable. See [Following one visitor](#following-one-visitor) |
| `SharedScoreDims` | `fp@host`, `fp`, `asn_fp@host`, `asn` | dimensions whose key covers many unrelated clients. They challenge but **never block, never revoke a clearance and never raise the proof-of-work difficulty or the challenge stage**: a botnet driving real Chrome through residential proxies carries the JA4 of every genuine Chrome user on the site, so both a block and a maximum-difficulty proof by that key hit people. Measured on live traffic: 165k botnet IPs solved 1 challenge out of 140k — the base challenge alone separates them |
| `HardReasons` | `fp@host`, `fp`, `asn_fp@host` | reasons that trigger the checkbox **regardless of score**. Needed for distributed networks: a client spread over thousands of IPs produces a low ratio and would otherwise keep getting cheap proof-of-work |

### Dimension limits (`Limits`)

Requests per `Window` (one minute by default) per key. This is the first
thing to tune for your traffic.

| Dimension | Default | Key | Catches |
|---|---|---|---|
| `ip_ua` | 200 | IP + UA hash | one client globally |
| `ip` | 400 | IP | everyone behind one address |
| `subnet` | 2500 | /24 or /64 | whole subnet |
| `ip_ua@host` | 120 | host + IP + UA | one client on one site |
| `ip@host` | 250 | host + IP | address on one site |
| `subnet@host` | 1500 | host + subnet | subnet on one site |
| `fp@host` | 200 | host + JA4 | **botnets and proxy networks**: thousands of IPs, one TLS stack |
| `fp` | 2000 | JA4 | the same, summed over every host: a botnet spread across a hundred sites stays under `fp@host` on each and adds up here |
| `asn_fp@host` | 900 | host + ASN + JA4 | distributed scraping from one datacenter |
| `asn` | 5000 | ASN | entire datacenter (hosting only) |

```go
p.Limits["fp@host"] = 400   // loosen
p.Limits["ip_ua@host"] = 80 // tighten
```

Dimensions you omit keep their defaults.

**How to pick values.** Look at the per-IP request distribution in your
logs: the p99.9 of a real user is your baseline, set the limit above it.
For `fp@host` look at the second most common fingerprint — the first one
is usually the botnet — and set the limit two or three times above it.

### Challenge

| Parameter | Default | Purpose |
|---|---|---|
| `BaseDifficulty` | `15` | leading zero bits in SHA-256. Each bit doubles the work. 15 ≈ 0.1 s on desktop, ~0.5 s on a phone |
| `MaxDifficulty` | `17` | ceiling. Above 20 weak phones take minutes and visitors close the tab |
| `TokenTTL` | `180s` | token lifetime. Too short and a slow device misses the window, then loops |
| `ClearanceTTL` | `1h` | how long a pass lasts after a solve. Too short and people re-solve constantly |

A pass is revoked only when the visitor burns through it themselves
(`cleared_abuse`), never on an ordinary challenge. Dropping it on every
challenge would trap people behind shared exits: VPN and Tor users share an IP
and a JA4, so a neighbour's traffic keeps the score high, every solve would be
undone and they would loop forever. Scrapers stay filtered because they never
solve the challenge in the first place.

### Network and trust

| Parameter | Default | Purpose |
|---|---|---|
| `TrustedASN` | `13335` (Cloudflare) | networks where "datacenter" means real people: WARP, iCloud Private Relay. Treated as residential, exempt from hosting penalties |
| `SkipPaths` | `/healthz`, `/metrics`, `/__bg/` | URL prefixes the guard leaves alone; yours are added to the defaults. Skipped requests are neither counted nor logged |
| `SkipFunc` | `nil` | the same as a function of the request — by host, extension, method, anything. Combined with `TrustedIPs`: either one skips |
| `TrustedIPs` | `127.0.0.1`, `::1` | your own addresses — monitoring, internal services. Bypass the guard entirely. Prefixes work: `"10.0."` covers the subnet |
| `ContactHTML` | empty | contact link on the denial page: `<a href="mailto:abuse@example.com">…</a>`. Empty hides the block. Worth filling in: someone blocked by mistake needs a way to reach you |
| `Window` | `1m` | rate counter window. If you change it, revisit `Limits` — they are per window |

### Custom bot rules

The built-in maps cover the common case, but every project has its own
specifics: a partner crawler to allow, internal monitoring, or a scraper
that targets you in particular. Rules from `Rules` are checked **first**
and override everything else.

```go
p.RulesMode = botguard.RulesAppend
p.Rules = []botguard.Rule{
    {Name: "AhrefsBot", Action: botguard.RuleAllow, Comment: "allowed here"},
    {Match: "BadScraper", Action: botguard.RuleBlock},
    {Match: "our-monitoring", Action: botguard.RuleAllow},
    {Name: "PartnerBot", Action: botguard.RuleKnownBot, ASNs: []uint32{64512}},
}
```

**Two modes:**

| Mode | Behaviour |
|---|---|
| `RulesAppend` | rules **extend** the built-in maps: anything not matched falls through to the standard lists. The usual choice |
| `RulesOverride` | rules **replace** the maps entirely: anything not matched goes through rate limiting only. For projects with their own policy |

**Matching:** by `Name` (exact name from the UA parser — `Googlebot`,
`AhrefsBot`) or by `Match` (case-insensitive UA substring). The first
matching rule wins, so order matters.

**Actions:**

| Action | Effect |
|---|---|
| `RuleAllow` | pass, skipping the score (statistics still recorded) |
| `RuleBlock` | 403 |
| `RuleChallenge` | challenge (proof-of-work or checkbox, by score) |
| `RuleKnownBot` | verify ASN: own network passes, foreign one is an impostor. Networks go in `ASNs` |
| `RuleScore` | normal path through rates and behaviour |

### Stats password

The page exposes visitor IPs and User-Agents, so lock it down on a public
domain:

```go
p.StatsUser = "admin"
p.StatsPassword = os.Getenv("BG_STATS_PASSWORD")
```

Basic auth on `/__bg/stats` and `/__bg/stats/reset`. Empty means open.
Comparison is constant-time, so the password cannot be guessed by timing.

### Statistics storage

| Parameter | Default | Purpose |
|---|---|---|
| `DB` | `nil` | connection for the fingerprint table, created on startup when missing. `nil` disables the store, the guard runs on Redis alone |
| `StoreDSN` | — | table name, e.g. `ja4.bg_fingerprints`. May be shared across projects |
| `StatsMaxBytes` | `2 GB` | how much of the log tail the stats page reads. A small cap silently shortens the period: with `LogAllowed` on the log gains hundreds of thousands of records an hour, and asking for an hour can return fourteen minutes. Raise it if the page warns about truncation — slower beats wrong |
| `SampleRate` | `1.0` | fraction of requests recorded. On heavy traffic 0.05–0.1 is plenty: the pairs matter, not exact counts |
| `Behavior` | `true` | behavioural layer (rhythm, catalogue crawling). Costs a second Redis call per request; disable if resources are tight |

---

## Logging

The package is not tied to any logging library — it needs a two-method
interface:

```go
type Logger interface {
    Info(msg string, keysAndValues ...any)
    Error(msg string, keysAndValues ...any)
}
```

Three lines on top of zap's SugaredLogger or slog:

```go
type myLog struct{ l *zap.SugaredLogger }
func (m myLog) Info(msg string, kv ...any)  { m.l.Infow(msg, kv...) }
func (m myLog) Error(msg string, kv ...any) { m.l.Errorw(msg, kv...) }
```

`botguard.StdLogger` wraps the standard `log` package if you have nothing
else. `Logger: nil` disables logging, but that also disables the stats
page — it reads the same file.

---

## Bot policy

Classification builds on `mileusna/useragent` (normalised names) and
`x-way/crawlerdetect` (curated pattern lists).

| Category | Treatment |
|---|---|
| Known search engines | ASN check: own network passes, foreign one gets challenged as an impostor |
| SEO scrapers | blocked (Ahrefs, Semrush, MJ12, DotBot, DataForSeo) |
| Tools | challenged (curl, wget, python, scrapy) |
| AI crawlers | controlled by `BlockAI` |
| Social preview bots without their own ASN | judged by behaviour, not by name (Discord, Slack, Facebook) |
| Apps that look like bots | passed (baiduboxapp, YandexSmartCamera, Yandex Browser) |

**A warning about search engine ASNs.** A company's ASN is not its
crawler's ASN. Verified on live traffic: Baidu comes through China Unicom
(AS4837), Yandex through Direct Cursus (AS212066), Sogou through CHINANET
(AS146966). Expect to extend the map from your logs, and check reverse DNS
before treating a bot as an impostor.

---

## Endpoints

| Path | Purpose |
|---|---|
| `/__bg/stats` | statistics (`?h=3` for three hours, `?format=json`) |
| `/__bg/stats/reset` | clear the log, POST |
| `/__bg/verify` | proof-of-work submission |
| `/__bg/checkbox` | checkbox result submission |
| `/__bg/captcha` | captcha answer submission |
| `/__bg/test-challenge` | preview the proof-of-work page |
| `/__bg/test-checkbox` | preview the checkbox page |
| `/__bg/test-captcha` | preview the captcha page |

All of them are in `SkipPaths`, so the guard does not count its own pages.
They are registered by `RegisterMux` / the adapters' `Register`; `Routes()`
lists them for a router that is not covered.

---

## Following one visitor

With `TrackingCookie` set and `bg:$upstream_http_x_bg_trk` in the nginx
`log_format`, one browser's requests line up by id instead of being merged by
a shared IP. `grep bg:<id>` over the access log reads as a fate:

```
503 bg:X                          the challenge — and nothing more:
                                  fetched the HTML, never ran the JS — a bot
503 bg:X → verify 200 bg:X → 200  solved and browsing — a person
503 bg:X → verify 200 bg:X → 503  solved but challenged again — an anomaly
                                  worth reporting
```

The id is a random opaque value: issued on first contact (the challenge 503
included), held for 30 days, never re-issued while the browser keeps it, and
never used in any decision. Static files served from the frontend cache carry
`bg:-` — the header only exists on responses that came from the backend.

---

## Frontend requirements

The guard sets cookies and serves per-visitor challenge pages, so a caching
proxy in front of it must leave those requests alone. Without this a visitor
can receive someone else's challenge token, or a cached page stripped of its
`Set-Cookie`, and end up solving the challenge over and over.

Exclude `/__bg/` from the cache entirely, and never cache a response carrying
a clearance cookie. In nginx:

```nginx
map $uri $bg_nocache {
    ~__bg   1;
    default 0;
}

proxy_cache_bypass $bg_nocache;
proxy_no_cache     $bg_nocache;
```

Two more things to check on the frontend:

- **`proxy_cache_key` must include everything that varies the response.** A
  key of `$uri` alone lets one cached page serve every visitor, and on a
  multi-site frontend it also merges different hosts into one entry.
- **`proxy_cache_use_stale` must not list `http_503`.** The challenge is
  served with 503, so a proxy told to reuse stale content on 503 will hand
  out an old page instead of the challenge.

Verify with the cache status in the access log: requests to `/__bg/` should
never show `HIT`, and challenge responses should always be `MISS` or `BYPASS`.

The guard also needs the visitor's real address and protocol, so forward
`X-Forwarded-For` and `X-Forwarded-Proto` — the latter decides whether the
clearance cookie is marked `Secure`.

---

## Referrer preservation

The challenge is served on the requested URL and the visitor leaves it with
`location.reload()`. Per the HTML spec a reload sends the current page as the
referrer, so a visit from a search engine would reach the application marked
as internal and analytics would count it as direct traffic.

The guard stashes the original referrer in a short-lived `bg_ref` cookie
before showing a challenge and restores the `Referer` header once the visitor
is through, so Matomo and your own code see the real source. The referrer is
stashed exactly as it arrived — external, internal or absent — because every
kind is distorted by the reload: a search visit turns into an internal hit and
a direct visit into a self-referral. Only the first challenged request is
stashed (later rounds carry our own page), the cookie is cleared after a
single use, and its value is validated before it goes back into the header.

Two consumers see the source, through two different mechanisms and with no
application changes:

- **Server code** reads the usual `Referer` header — the guard rewrites it on
  the request before handing it to the application, in every mode.
- **Client-side analytics** (Matomo and the like) read `document.referrer`,
  which no header can fix: the real page never loaded on the first visit, so
  no script had a chance to record the source, and after the challenge the
  browser reports our own URL. How the source reaches the client side is
  selected by `RefererMode`:

| `RefererMode` | Behaviour |
|---|---|
| `"inject"` (default) | a one-line `document.referrer` shim is injected right after `<head>` of the first HTML page after a pass, before any analytics script runs. Only plain 200 HTML responses are touched; anything compressed, non-HTML or without a `<head>` in the first chunk passes through untouched |
| `"param"` | the first request after a pass is redirected once to the same URL with the source appended as a query parameter (`RefererParam`, default `bg_ref`). Nothing is injected, but the page URL changes — mind canonical URLs and caches |
| `"both"` | the redirect adds the parameter and the landing page gets the shim as well |
| `"off"` | only the header. Client-side analytics keep seeing the challenge page as the referrer |

Matomo itself has no native query parameter for the raw referrer (campaign
parameters like `mtm_source` exist but describe campaigns, and
`setReferrerUrl` needs tracking-code changes), which is why the shim is the
default.

The `Secure` flag follows the connection: it is set on HTTPS (including behind
a proxy that sends `X-Forwarded-Proto`) and omitted on plain HTTP, where it
would make the browser drop the cookie.

---

## Running without JA4

If the frontend does not set `X-JA4` (or sends `-`, as happens behind
Cloudflare), the fingerprint falls back to HTTP headers: `Accept`,
`Sec-Ch-Ua`, `Sec-Fetch-*` and the protocol version. It is weaker — header
spoofing defeats it — but fingerprint dimensions keep working.

---

## Database

The fingerprint store works on **MySQL**, **PostgreSQL** and **SQLite**.
The dialect is detected from the driver behind `*sql.DB` (pgx and pq are
Postgres, mattn and modernc are SQLite, anything else is MySQL) and can be
forced with `StoreDialect`:

```go
p.DB           = pgxPool       // *sql.DB from database/sql
p.StoreDSN     = "bg_fingerprints"
p.StoreDialect = "postgres"    // "mysql" | "postgres" | "sqlite"; empty = detect
```

The table is created on startup when it is missing: the guard probes it
with a `SELECT`, runs the DDL for the dialect if that fails, then reads it
back to confirm the table is really usable — a `CREATE` can succeed while
`SELECT` still fails on insufficient rights or a stale schema cache.

If it cannot be created either — no rights, a database that is down, a name
that collides with something else — the fingerprint store is switched off
and the reason is reported through `OnError`. The guard keeps working on
Redis alone. Statistics are worth losing; the guard failing over them is not.

The DDL follows the configured table name, so a schema-qualified name such
as `ja4.bg_fingerprints` works on MySQL and Postgres. `SchemaSQL` holds the
MySQL DDL, `SchemaFor(dialect, table)` returns the statements for any
dialect. Writes are batched upserts (`ON DUPLICATE KEY UPDATE` on MySQL,
`ON CONFLICT DO UPDATE` elsewhere) with the counters adding up.

---

## Rollout

1. `Enforce: false` — monitor for a week.
2. Watch `/__bg/stats`: the "blocked UA" and "failed by stage" cards expose
   false positives. A real browser under block means the maps need work.
3. Tune `Limits` for your traffic.
4. `Enforce: true`.

Fixing the maps is cheaper before they start hitting real visitors.
