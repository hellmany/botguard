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

// The site-wide fingerprint count ignores network-type multipliers (a
// botnet through "business" ranges was getting a 4x limit for free), while
// per-host dimensions keep them: phones behind carrier NAT need the room.
func TestGlobalFingerprintIgnoresNATFactor(t *testing.T) {
	g := testGuard(t)
	s := Signals{UsageType: "business"}
	for _, d := range dimensionsB() {
		f := g.limitFactor(d, s)
		switch d.Name {
		case "fp":
			if f != 1 {
				t.Errorf("fp: factor %v, want 1", f)
			}
		case "fp@host", "ip":
			if f == 1 {
				t.Errorf("%s must keep the NAT relaxation", d.Name)
			}
		}
	}
}
