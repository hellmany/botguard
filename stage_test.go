package botguard

import "testing"

// HardReasons lift a low fp@host score to the checkbox; a disabled stage
// (threshold 0) never fires.
func TestStageShownFor(t *testing.T) {
	oldCb, oldCap, oldHR := bgCheckboxAt, bgCaptchaAt, bgHardReasons
	defer func() { bgCheckboxAt, bgCaptchaAt, bgHardReasons = oldCb, oldCap, oldHR }()

	bgCheckboxAt, bgCaptchaAt = 6.0, 0 // captcha disabled
	bgHardReasons = []string{"score:fp@host", "score:asn_fp@host"}

	cases := []struct {
		name   string
		score  float64
		reason string
		want   string
	}{
		{"botnet by fingerprint", 1.9, "score:fp@host", "checkbox (by reason)"},
		{"botnet from a datacenter", 1.2, "score:asn_fp@host", "checkbox (by reason)"},
		{"ordinary overage", 2.5, "score:ip_ua@host", "PoW"},
		{"large overage", 7.0, "score:ip_ua@host", "checkbox"},
		{"browser from a datacenter", 1.0, "hosting_browser", "PoW"},
		// with the captcha disabled a high score still yields the checkbox
		{"very high score", 50.0, "score:ip_ua@host", "checkbox"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stageShownFor(c.score, c.reason); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// InitStats assigns thresholds unconditionally: zero disables the stage.
func TestInitStatsZeroDisables(t *testing.T) {
	oldCb, oldCap, oldHR := bgCheckboxAt, bgCaptchaAt, bgHardReasons
	defer func() { bgCheckboxAt, bgCaptchaAt, bgHardReasons = oldCb, oldCap, oldHR }()

	bgCaptchaAt = 12.0 // leftover from an earlier configuration
	InitStats(Params{CheckboxAt: 6.0, CaptchaAt: 0})

	if bgCaptchaAt != 0 {
		t.Fatalf("bgCaptchaAt=%v, want 0 (captcha disabled)", bgCaptchaAt)
	}
	if got := stageShownFor(50.0, "score:ip_ua@host"); got == "captcha" {
		t.Errorf("captcha is disabled but got %q", got)
	}
}
