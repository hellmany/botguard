package botguard

import (
	"testing"
)

type capture struct{ msgs []string }

func (c *capture) Info(msg string, kv ...any)  { c.msgs = append(c.msgs, msg) }
func (c *capture) Error(msg string, kv ...any) {}

// Allow verdicts are logged only with LogAllowed on.
func TestLogAllowedGatesPassingVerdicts(t *testing.T) {
	for _, on := range []bool{false, true} {
		p := DefaultParams()
		p.Secret = "0123456789abcdef0123456789abcdef"
		p.LogAllowed = on
		cap := &capture{}
		p.Logger = cap
		g, err := New(nil, NewConfig(p))
		if err != nil {
			t.Fatal(err)
		}
		g.logVerdict(Verdict{Decision: Allow, Cleared: true})
		got := len(cap.msgs) > 0
		if got != on {
			t.Errorf("LogAllowed=%v: logged=%v, want %v", on, got, on)
		}
	}
}

// Challenges and blocks are logged either way.
func TestNonAllowAlwaysLogged(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	cap := &capture{}
	p.Logger = cap
	g, _ := New(nil, NewConfig(p))
	g.logVerdict(Verdict{Decision: Challenge, Reason: "score:fp@host"})
	if len(cap.msgs) == 0 {
		t.Error("a challenge must be logged even with LogAllowed off")
	}
}
