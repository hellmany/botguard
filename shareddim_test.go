package botguard

import "testing"

func TestSharedDimDefaults(t *testing.T) {
	g := testGuard(t)
	for dim, want := range map[string]bool{
		"fp@host": true, "fp": true, "asn_fp@host": true, "asn": true,
		"ip_ua@host": false, "ip": false, "subnet@host": false,
	} {
		if got := g.isSharedDim(dim); got != want {
			t.Errorf("isSharedDim(%q) = %v, want %v", dim, got, want)
		}
	}
}

func TestSharedDimOverride(t *testing.T) {
	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.SharedScoreDims = []string{"subnet@host"}
	g, _ := New(nil, NewConfig(p))
	if !g.isSharedDim("subnet@host") || g.isSharedDim("fp@host") {
		t.Error("override not honoured")
	}
}

// A shared dimension's overflow does not raise the proof-of-work difficulty.
func TestSharedScoreDoesNotRaiseDifficulty(t *testing.T) {
	g := testGuard(t)
	v := Verdict{Score: 300, Reason: "score:fp@host"}
	if eff := g.effChallengeScore(v); eff != g.cfg.Thresholds.ChallengeAt {
		t.Errorf("shared overflow leaked into the difficulty: eff=%v", eff)
	}
	if d := g.difficultyFor(g.effChallengeScore(v)); d != g.cfg.Challenge.BaseDifficulty {
		t.Errorf("difficulty %d, want the base", d)
	}

	// A personal overflow still escalates.
	v = Verdict{Score: 300, Reason: "score:ip_ua@host"}
	if d := g.difficultyFor(g.effChallengeScore(v)); d != g.cfg.Challenge.MaxDifficulty {
		t.Errorf("personal overflow must escalate, got %d", d)
	}
}
