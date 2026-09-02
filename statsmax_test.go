package botguard

import "testing"

func TestStatsMaxBytesConfigurable(t *testing.T) {
	orig := bgStatsMaxBytes
	defer func() { bgStatsMaxBytes = orig }()

	p := DefaultParams()
	p.Secret = "0123456789abcdef0123456789abcdef"
	p.StatsMaxBytes = 8 << 30
	InitStats(p)
	if bgStatsMaxBytes != 8<<30 {
		t.Errorf("cap = %d, want 8 GB", bgStatsMaxBytes)
	}

	// Zero must leave the default alone rather than read nothing.
	bgStatsMaxBytes = orig
	p.StatsMaxBytes = 0
	InitStats(p)
	if bgStatsMaxBytes != orig {
		t.Errorf("zero changed the cap to %d", bgStatsMaxBytes)
	}
}

// The default cap covers an hour of a busy site with LogAllowed on.
func TestDefaultStatsCapCoversAnHour(t *testing.T) {
	const perRecord = 400 // bytes per log line
	const hourly = 2_300_000
	if need := int64(perRecord) * hourly; bgStatsMaxBytes < need {
		t.Errorf("cap %d MB is below the %d MB an hour needs", bgStatsMaxBytes>>20, need>>20)
	}
}
