package botguard

import (
	"strings"
	"testing"
)

// Browser versions look like an IPv4 and must not be linkified.
func TestLinkifyIPsSkipsBrowserVersions(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"
	if out := linkifyIPs(ua); strings.Contains(out, "<a ") {
		t.Errorf("a browser version was linkified:\n%s", out)
	}
}

func TestLinkifyIPsStillLinksRealIPs(t *testing.T) {
	for _, in := range []string{
		"84.32.231.78 (AS1234)",          // at the start
		"score:ip@host 84.32.231.78 hit", // mid-string
	} {
		out := linkifyIPs(in)
		if !strings.Contains(out, `href="https://ipinfo.io/84.32.231.78"`) {
			t.Errorf("%q: real IP not linked:\n%s", in, out)
		}
	}
}
