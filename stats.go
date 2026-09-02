// stats.go serves the botguard web stats built from the verdict log.
// GET /__bg/stats             — summary for the last hour (HTML)
// GET /__bg/stats?h=3         — for the last 3 hours
// GET /__bg/stats?format=json — the same as JSON
//
// The log is read from the END (last N MB) to avoid pulling in a gigabyte file.
package botguard

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// bgLogPath is the path to the verdict log, set through Params.LogPath.
var bgLogPath string

// bgStoreTable is the fingerprint stats table, also set from the outside.
var bgStoreTable string

// bgStoreDB is the connection used to read the challenge counters.
var bgStoreDB *sql.DB

// bgStatsMaxBytes caps how much is read from the end of the log. A small cap
// silently shortens the period the page covers, so the default is large.
// Set with Params.StatsMaxBytes.
var bgStatsMaxBytes int64 = 2 << 30 // 2 GB

// InitStats configures the stats page from the application parameters.
func InitStats(p Params) {
	if p.LogPath != "" {
		bgLogPath = p.LogPath
	}
	if p.StatsMaxBytes > 0 {
		bgStatsMaxBytes = p.StatsMaxBytes
	}
	if p.StoreDSN != "" {
		bgStoreTable = p.StoreDSN
	}
	bgStoreDB = p.DB
	// Assigned unconditionally: zero means the stage is disabled.
	bgCheckboxAt = p.CheckboxAt
	bgCaptchaAt = p.CaptchaAt
	bgHardReasons = p.HardReasons
	bgLogger = p.Logger
	bgStatsUser, bgStatsPass = p.StatsUser, p.StatsPassword
}

// stageOf derives the challenge stage from the reason recorded in the log.
// The stages write different reasons: PoW writes "solved"/"bad proof", the
// captcha "captcha *", the checkbox "checkbox*".
func stageOf(reason string) string {
	switch {
	case strings.HasPrefix(reason, "captcha"):
		return "captcha"
	case strings.HasPrefix(reason, "checkbox"):
		return "checkbox"
	default:
		return "PoW"
	}
}

// stageShownFor reports which stage the client saw, mirroring the middleware:
// captcha by score, then checkbox by score or by a hard reason.
func stageShownFor(score float64, reason string) string {
	switch {
	// A threshold of 0 means the stage is disabled.
	case bgCaptchaAt > 0 && score >= bgCaptchaAt:
		return "captcha"
	case bgCheckboxAt > 0 && score >= bgCheckboxAt:
		return "checkbox"
	case isHardReasonName(reason):
		return "checkbox (by reason)"
	default:
		return "PoW"
	}
}

func isHardReasonName(reason string) bool {
	for _, hr := range bgHardReasons {
		if hr != "" && strings.HasPrefix(reason, hr) {
			return true
		}
	}
	return false
}

// Thresholds and hard reasons for the page, filled in by InitStats.
var (
	bgCheckboxAt, bgCaptchaAt float64
	bgHardReasons             []string
)

// bgRecord is one verdict log line.
type bgRecord struct {
	TS       string  `json:"ts"`
	Decision string  `json:"decision"`
	Reason   string  `json:"reason"`
	Host     string  `json:"host"`
	IP       string  `json:"ip"`
	UAKind   string  `json:"ua_kind"`
	UA       string  `json:"ua"`
	JA4      string  `json:"ja4"`
	ASN      uint32  `json:"asn"`
	Org      string  `json:"org"` // organization from X-Organization (nginx/geoip2)
	Usage    string  `json:"usage"`
	CC       string  `json:"cc"`
	Score    float64 `json:"score"`
}

type bgCounter map[string]int

func (c bgCounter) add(k string) {
	if k != "" {
		c[k]++
	}
}

// topN returns the sorted key/value pairs, capped at n.
func (c bgCounter) topN(n int) []bgPair {
	out := make([]bgPair, 0, len(c))
	for k, v := range c {
		out = append(out, bgPair{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].K < out[j].K
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type bgPair struct {
	K string `json:"key"`
	N int    `json:"count"`
}

type bgStats struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Hours     int      `json:"hours"`
	Total     int      `json:"total"`
	Decisions []bgPair `json:"decisions"`
	Reasons   []bgPair `json:"reasons"`
	// reasons broken down WITHIN each decision
	ByDecision map[string][]bgPair `json:"by_decision"`
	UAKinds    []bgPair            `json:"ua_kinds"`
	TopIPs     []bgPair            `json:"top_ips"`
	TopHosts   []bgPair            `json:"top_hosts"`
	TopASN     []bgPair            `json:"top_asn"`
	TopUA      []bgPair            `json:"top_ua"`
	// UA and IP per decision.
	BlockedUA    []bgPair `json:"blocked_ua"`
	ChallengedUA []bgPair `json:"challenged_ua"`
	BlockedIP    []bgPair `json:"blocked_ip"`
	ChallengedIP []bgPair `json:"challenged_ip"`
	// UAs that failed and solved the challenge.
	FailedUA []bgPair `json:"failed_challenge_ua"`
	SolvedUA []bgPair `json:"solved_challenge_ua"`
	// reason plus UA on one line
	ReasonUA []bgPair `json:"reason_ua"`
	// Per stage (PoW / checkbox / captcha): shown, solved, failed.
	StageShown  []bgPair `json:"stage_shown"`
	StageSolved []bgPair `json:"stage_solved"`
	StageFailed []bgPair `json:"stage_failed"`
	// IPs caught by the rate limits (score:*).
	FreqIPs  []bgPair `json:"freq_limited_ips"`
	FakeBots []bgPair `json:"fake_bots"`
	// Declared bots absent from every map; candidates for the known lists.
	UnknownBots []bgPair `json:"unknown_bots"`
	// AI crawlers, counted separately from the unknowns.
	AIBots    []bgPair `json:"ai_bots"`
	Truncated bool     `json:"truncated"`
	// Challenge pass rate from the fingerprint store, cumulative.
	Challenge bgChallengeStats `json:"challenge"`
}

type bgChallengeStats struct {
	Challenged int64   `json:"challenged"`
	Solved     int64   `json:"solved"`
	Failed     int64   `json:"failed"`
	SolveRate  float64 `json:"solve_rate_pct"`
	Err        string  `json:"error,omitempty"`
}

// challengeStats reads the cumulative challenge counters from the store.
func challengeStats() bgChallengeStats {
	var s bgChallengeStats
	if bgStoreDB == nil {
		s.Err = "no database connection"
		return s
	}
	row := bgStoreDB.QueryRow(`SELECT COALESCE(SUM(challenged),0), COALESCE(SUM(solved),0),
	    COALESCE(SUM(failed),0) FROM ` + bgStoreTable)
	if err := row.Scan(&s.Challenged, &s.Solved, &s.Failed); err != nil {
		s.Err = err.Error()
		return s
	}
	if s.Challenged > 0 {
		s.SolveRate = float64(s.Solved) * 100 / float64(s.Challenged)
	}
	return s
}

// collectBGStats reads the tail of the log and aggregates the records of the
// last hours hours.
func collectBGStats(hours int) (*bgStats, error) {
	f, err := os.Open(bgLogPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st := &bgStats{Hours: hours}
	if fi.Size() > bgStatsMaxBytes {
		if _, err := f.Seek(-bgStatsMaxBytes, 2); err != nil {
			return nil, err
		}
		st.Truncated = true
	}

	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	const tsLayout = "2006-01-02 15:04:05" // UTC in the log

	dec := bgCounter{}
	reasons := bgCounter{}
	kinds := bgCounter{}
	ips := bgCounter{}
	hosts := bgCounter{}
	asns := bgCounter{}
	uas := bgCounter{}
	fakes := bgCounter{}
	unknown := bgCounter{}
	aiSeen := bgCounter{}
	byDec := map[string]bgCounter{}
	asnOrg := map[string]bgCounter{} // ASN -> org name counts
	blockedUA := bgCounter{}
	challengedUA := bgCounter{}
	blockedIP := bgCounter{}
	challengedIP := bgCounter{}
	failedUA := bgCounter{}
	solvedUA := bgCounter{}
	reasonUA := bgCounter{}
	freqIPs := bgCounter{}
	stageShown := bgCounter{}
	stageSolved := bgCounter{}
	stageFailed := bgCounter{}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 128*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue // the first line after Seek is usually truncated
		}
		var r bgRecord
		if json.Unmarshal(line, &r) != nil {
			continue
		}
		if r.Decision == "" {
			continue
		}
		t, err := time.Parse(tsLayout, r.TS)
		if err != nil || t.Before(cutoff) {
			continue
		}
		if first {
			st.From = r.TS
			first = false
		}
		st.To = r.TS
		st.Total++

		dec.add(r.Decision)
		reasons.add(r.Reason)
		kinds.add(r.UAKind)
		if r.Org != "" {
			ips.add(r.IP + " (" + r.Org + ")")
		} else {
			ips.add(r.IP)
		}
		hosts.add(r.Host)
		if r.ASN != 0 {
			key := "AS" + strconv.FormatUint(uint64(r.ASN), 10)
			asns.add(key)
			// One ASN arrives under several org spellings; the most frequent
			// one goes into the label.
			if r.Org != "" {
				if asnOrg[key] == nil {
					asnOrg[key] = bgCounter{}
				}
				asnOrg[key].add(truncUA(r.Org, 40))
			}
		}
		// Not truncated: bot markers usually sit at the end of the UA.
		ua := r.UA
		if ua == "" {
			ua = "(empty UA)"
		}
		uas.add(ua)
		// With the organization, to tell hosting from an ISP.
		ipLabel := r.IP
		if r.Org != "" {
			ipLabel += " (" + r.Org + ")"
		} else if r.ASN != 0 {
			ipLabel += " (AS" + strconv.FormatUint(uint64(r.ASN), 10) + ")"
		}
		switch r.Decision {
		case "block":
			blockedUA.add(ua)
			blockedIP.add(ipLabel)
		case "challenge":
			challengedUA.add(ua)
			challengedIP.add(ipLabel)
			stageShown.add(stageShownFor(r.Score, r.Reason))
		case "challenge_failed":
			failedUA.add(ua)
			stageFailed.add(stageOf(r.Reason) + " · " + r.Reason)
		case "challenge_solved":
			solvedUA.add(ua)
			stageSolved.add(stageOf(r.Reason))
		}
		if r.Reason != "" {
			// Rate reasons are keyed by IP and host, the rest by UA.
			if strings.HasPrefix(r.Reason, "score:") {
				who := r.IP
				if r.Org != "" {
					who += " (" + r.Org + ")"
				} else if r.ASN != 0 {
					who += " (AS" + strconv.FormatUint(uint64(r.ASN), 10) + ")"
				}
				reasonUA.add(r.Reason + "  ←  " + who + " → " + r.Host)
				freqIPs.add(who + " → " + r.Host + "  (" + r.Decision + ")")
			} else {
				reasonUA.add(r.Reason + "  ←  " + truncUA(r.UA, 60))
			}
		}
		if strings.HasPrefix(r.Reason, "fake_bot:") {
			fakes.add(strings.TrimPrefix(r.Reason, "fake_bot:"))
		}
		if r.Reason == "unknown_bot_allow" {
			unknown.add(ua)
		}
		if r.Reason == "ai_crawler_allow" {
			aiSeen.add(ua)
		}
		if byDec[r.Decision] == nil {
			byDec[r.Decision] = bgCounter{}
		}
		byDec[r.Decision].add(r.Reason)
	}

	st.Decisions = dec.topN(10)
	st.Reasons = reasons.topN(20)
	st.UAKinds = kinds.topN(10)
	st.TopIPs = ips.topN(15)
	st.TopHosts = hosts.topN(15)
	st.TopASN = asns.topN(15)
	// Label every ASN with its most frequent organization name.
	for i, p := range st.TopASN {
		if orgs := asnOrg[p.K]; len(orgs) > 0 {
			if top := orgs.topN(1); len(top) > 0 {
				st.TopASN[i].K = p.K + " · " + top[0].K
			}
		}
	}
	st.TopUA = uas.topN(15)
	st.BlockedUA = blockedUA.topN(20)
	st.ChallengedUA = challengedUA.topN(20)
	st.BlockedIP = blockedIP.topN(20)
	st.ChallengedIP = challengedIP.topN(20)
	st.FailedUA = failedUA.topN(15)
	st.SolvedUA = solvedUA.topN(15)
	st.ReasonUA = reasonUA.topN(25)
	st.StageShown = stageShown.topN(6)
	st.StageSolved = stageSolved.topN(6)
	st.StageFailed = stageFailed.topN(12)
	st.FreqIPs = freqIPs.topN(20)
	st.FakeBots = fakes.topN(15)
	st.UnknownBots = unknown.topN(20)
	st.AIBots = aiSeen.topN(20)
	st.ByDecision = map[string][]bgPair{}
	for d, c := range byDec {
		st.ByDecision[d] = c.topN(12)
	}
	st.Challenge = challengeStats()
	return st, nil
}

// noteStatsReset marks the moment of the reset in the cleared log.
func noteStatsReset() {
	if bgLogger != nil {
		bgLogger.Info("stats_reset", "decision", "-", "reason", "log cleared")
	}
}

// bgLogger is the application logger used by the stats page.
var bgLogger Logger

// Basic Auth for the stats page. Empty means no password.
var bgStatsUser, bgStatsPass string

func truncUA(s string, n int) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) > n {
		return s[:n]
	}
	return s
}

func renderBGStatsHTML(st *bgStats) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>botguard stats</title><style>
body{font:14px/1.5 system-ui,-apple-system,sans-serif;margin:0;padding:20px;background:#f7f7f8;color:#222}
h1{font-size:18px;margin:0 0 4px}h2{font-size:14px;margin:20px 0 8px;color:#444;
   text-transform:uppercase;letter-spacing:.04em}
.meta{color:#777;font-size:13px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(440px,1fr));gap:16px}
.card{background:#fff;border:1px solid #e3e3e6;border-radius:8px;padding:14px;overflow:hidden}
table{width:100%;border-collapse:collapse}
td{padding:3px 0;vertical-align:top}
td.n{text-align:right;font-variant-numeric:tabular-nums;color:#555;white-space:nowrap;padding-left:10px}
td.k{word-break:break-word;overflow-wrap:anywhere;line-height:1.35;
     font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}
.bar{height:3px;background:#4a7fd0;border-radius:2px;margin-top:2px}
a{color:#0066cc;text-decoration:none}.nav a{margin-right:12px}
.warn{background:#fff6e0;border:1px solid #f0d9a0;padding:8px 12px;border-radius:6px;margin-bottom:14px}
</style></head><body>`)

	fmt.Fprintf(&b, `<h1>botguard — stats</h1>`)
	fmt.Fprintf(&b, `<div class="meta">records: <b>%d</b> · period: %s — %s (last %d h)</div>`,
		st.Total, html.EscapeString(st.From), html.EscapeString(st.To), st.Hours)
	b.WriteString(`<div class="nav">period: `)
	for _, h := range []int{1, 3, 6, 12, 24} {
		fmt.Fprintf(&b, `<a href="?h=%d&force=1">%dh</a>`, h, h)
	}
	b.WriteString(`<a href="?h=1&force=1&format=json">json</a>`)
	// A POST with a confirmation, so a stray click cannot wipe the log.
	b.WriteString(`<form method="post" action="/__bg/stats/reset" style="display:inline"` +
		` onsubmit="return confirm('Clear the stats log? Everything collected so far will be deleted.')">` +
		`<button type="submit" style="font:inherit;color:#c0392b;background:none;border:none;` +
		`cursor:pointer;padding:0;text-decoration:underline">clear stats</button></form>`)
	b.WriteString(`</div>`)

	if st.Truncated {
		fmt.Fprintf(&b, `<div class="warn">The log is larger than %d MB — only the tail was read, `+
			`so early records in the period may be missing. Raise StatsMaxBytes to cover it.</div>`,
			bgStatsMaxBytes>>20)
	}
	if st.Total == 0 {
		b.WriteString(`<p>No records in the selected period.</p></body></html>`)
		return b.String()
	}

	// Challenge pass rate, cumulative.
	ch := st.Challenge
	if ch.Err == "" && ch.Challenged > 0 {
		notSolved := ch.Challenged - ch.Solved
		fmt.Fprintf(&b, `<div class="card" style="margin-bottom:16px">`+
			`<h2>Challenge pass rate (all time)</h2><table>`+
			`<tr><td class="k">shown</td><td class="n">%d</td></tr>`+
			`<tr><td class="k">solved (real browser)</td><td class="n">%d<br><span style="color:#999">%.1f%%</span></td></tr>`+
			`<tr><td class="k">not solved (left or bot)</td><td class="n">%d<br><span style="color:#999">%.1f%%</span></td></tr>`+
			`<tr><td class="k">failed (bad answer)</td><td class="n">%d</td></tr>`+
			`</table></div>`,
			ch.Challenged, ch.Solved, ch.SolveRate,
			notSolved, 100-ch.SolveRate, ch.Failed)
	} else if ch.Err != "" {
		fmt.Fprintf(&b, `<div class="warn">Challenge counters unavailable: %s</div>`,
			html.EscapeString(ch.Err))
	}

	b.WriteString(`<div class="grid">`)
	card(&b, "Decisions", st.Decisions, st.Total)
	card(&b, "UA kinds", st.UAKinds, st.Total)
	// reasons within each decision
	decOrder := []string{"block", "challenge", "too_many", "allow"}
	for _, d := range decOrder {
		if rows, ok := st.ByDecision[d]; ok {
			card(&b, "Reasons → "+d, rows, st.Total)
		}
	}
	if len(st.UnknownBots) > 0 {
		card(&b, "❓ Unknown bots (allowed) — to classify", st.UnknownBots, st.Total)
	}
	if len(st.AIBots) > 0 {
		card(&b, "🤖 AI crawlers (allowed)", st.AIBots, st.Total)
	}
	if len(st.FakeBots) > 0 {
		card(&b, "Impostors (fake_bot)", st.FakeBots, st.Total)
	}
	if len(st.StageShown) > 0 {
		card(&b, "🎫 shown by stage", st.StageShown, st.Total)
	}
	if len(st.StageSolved) > 0 {
		card(&b, "✅ solved by stage", st.StageSolved, st.Total)
	}
	if len(st.StageFailed) > 0 {
		card(&b, "❌ failed by stage", st.StageFailed, st.Total)
	}
	card(&b, "⛔ BLOCKED UA", st.BlockedUA, st.Total)
	card(&b, "⛔ BLOCKED IP", st.BlockedIP, st.Total)
	card(&b, "🔒 CHALLENGED UA", st.ChallengedUA, st.Total)
	card(&b, "🔒 CHALLENGED IP", st.ChallengedIP, st.Total)
	if len(st.SolvedUA) > 0 {
		card(&b, "✅ passed the challenge (real)", st.SolvedUA, st.Total)
	}
	if len(st.FailedUA) > 0 {
		card(&b, "❌ failed the challenge", st.FailedUA, st.Total)
	}
	if len(st.FreqIPs) > 0 {
		card(&b, "📊 IP over the rate limit (score:*)", st.FreqIPs, st.Total)
	}
	card(&b, "Reason ← who", st.ReasonUA, st.Total)
	card(&b, "All reasons", st.Reasons, st.Total)
	card(&b, "Top IPs", st.TopIPs, st.Total)
	card(&b, "Top ASNs", st.TopASN, st.Total)
	card(&b, "Top hosts", st.TopHosts, st.Total)
	card(&b, "Top User-Agents", st.TopUA, st.Total)
	b.WriteString(`</div></body></html>`)
	return b.String()
}

// ipInText finds an IPv4 in a string. The guard before the address skips
// browser versions such as "Chrome/145.0.0.0", which follow a slash.
var ipInText = regexp.MustCompile(`(^|[^/\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// linkifyIPs turns IPs into ipinfo.io links; the input is already escaped.
func linkifyIPs(escaped string) string {
	return ipInText.ReplaceAllString(escaped,
		`$1<a href="https://ipinfo.io/$2" target="_blank" rel="noopener">$2</a>`)
}

func card(b *strings.Builder, title string, rows []bgPair, total int) {
	if len(rows) == 0 {
		return
	}
	max := rows[0].N
	fmt.Fprintf(b, `<div class="card"><h2>%s</h2><table>`, html.EscapeString(title))
	for _, r := range rows {
		pct := 0.0
		if total > 0 {
			pct = float64(r.N) * 100 / float64(total)
		}
		w := 0
		if max > 0 {
			w = r.N * 100 / max
		}
		fmt.Fprintf(b, `<tr><td class="k">%s<div class="bar" style="width:%d%%"></div></td>`+
			`<td class="n">%d<br><span style="color:#999">%.1f%%</span></td></tr>`,
			linkifyIPs(html.EscapeString(r.K)), w, r.N, pct)
	}
	b.WriteString(`</table></div>`)
}
