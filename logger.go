// Logging contract. The application supplies its own implementation through
// Params.Logger; keys and values come in pairs, as in slog.
package botguard

import (
	"fmt"
	"log"
	"strings"
)

// Logger is what botguard expects from the application.
//
//	type myLog struct{ l *zap.SugaredLogger }
//	func (m myLog) Info(msg string, kv ...any)  { m.l.Infow(msg, kv...) }
//	func (m myLog) Error(msg string, kv ...any) { m.l.Errorw(msg, kv...) }
type Logger interface {
	Info(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

// nopLogger is used when no logger is set.
type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// StdLogger wraps the standard log package for applications without their
// own logger. Writes a single line: msg key=value.
type StdLogger struct{ L *log.Logger }

func (s StdLogger) Info(msg string, kv ...any)  { s.write("INFO", msg, kv) }
func (s StdLogger) Error(msg string, kv ...any) { s.write("ERROR", msg, kv) }

func (s StdLogger) write(level, msg string, kv []any) {
	var b strings.Builder
	b.WriteString(level)
	b.WriteByte(' ')
	b.WriteString(msg)
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, " %v=%v", kv[i], kv[i+1])
	}
	if s.L != nil {
		s.L.Println(b.String())
		return
	}
	log.Println(b.String())
}

// logVerdict is the single place a verdict becomes a log record. The format
// matches what the stats page parses.
func (g *Guard) logVerdict(v Verdict) {
	if v.Decision == Allow && !g.cfg.LogAllowed {
		return // allows dominate the log
	}
	g.log.Info("verdict",
		"decision", v.Decision.String(),
		"score", v.Score,
		"reason", v.Reason,
		"host", v.Signals.Host,
		"ip", v.Signals.IPStr,
		"ua_kind", v.Signals.UAKind.String(),
		"ua", v.Signals.UA,
		"ja4", v.Signals.FPrint,
		"asn", v.Signals.ASN,
		"org", v.Signals.ASNOrg,
		"usage", v.Signals.UsageType,
		"cc", v.Signals.Country,
		"cleared", v.Cleared,
		// as the application sees it: after a challenge the restored source
		"ref", v.Signals.Referer,
	)
}

// logChallengeResult records the outcome of a challenge and which stage it was.
func (g *Guard) logChallengeResult(ok bool, reason string, s Signals) {
	res := "challenge_failed"
	if ok {
		res = "challenge_solved"
	}
	g.log.Info("challenge",
		"decision", res,
		"reason", reason,
		"host", s.Host,
		"ip", s.IPStr,
		"ua", s.UA,
		"ja4", s.FPrint,
		"asn", s.ASN,
		"org", s.ASNOrg,
		"usage", s.UsageType,
		"cc", s.Country,
	)
}

// logRefRestored records the restored traffic source; the verdict itself is
// logged before the restore.
func (g *Guard) logRefRestored(v Verdict, ref string) {
	g.log.Info("ref_restored",
		"host", v.Signals.Host,
		"ip", v.Signals.IPStr,
		"was", v.Signals.Referer,
		"ref", ref,
	)
}
