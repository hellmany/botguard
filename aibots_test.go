package botguard

import "testing"

// mileusna names none of these, so they are matched by substring.
func TestAICrawlersMatchedBySubstring(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "GPTBot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "ClaudeBot"},
		{"Mozilla/5.0 (compatible; ExaSearchBot/1.0; +https://crawler.exa.ai/)", "ExaSearchBot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)", "Amazonbot"},
		{"Mozilla/5.0 (compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)", "Perplexity-User"},
	}
	for _, c := range cases {
		kind, name := classifyUAlib(c.ua)
		if kind != UAAIBot || name != c.want {
			t.Errorf("%q -> (%v, %q), want (UAAIBot, %q)", c.ua[:50], kind, name, c.want)
		}
	}
}

// Blacklisted bots are matched by substring too.
func TestBlacklistedBotsMatchedBySubstring(t *testing.T) {
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; AwarioBot/1.0; +https://awario.com/bots.html)",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
	} {
		if kind, _ := classifyUAlib(ua); kind != UABadBot {
			t.Errorf("%q -> %v, want UABadBot", ua[:45], kind)
		}
	}
}

// A plain browser must not trip the substring match.
func TestAISubstringDoesNotCatchBrowsers(t *testing.T) {
	kind, name := classifyUAlib("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	if kind != UABrowser || name != "" {
		t.Errorf("browser misclassified: (%v, %q)", kind, name)
	}
}
