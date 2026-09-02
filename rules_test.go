package botguard

import "testing"

// Custom rules win over the built-in maps.
func TestCustomRules(t *testing.T) {
	old, oldMode := customRules, customRulesMode
	defer func() { customRules, customRulesMode = old, oldMode }()

	ahrefs := "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
	partner := "PartnerCrawler/1.0 (+https://partner.example.com/bot)"

	t.Run("append: own rule beats the built-in blacklist", func(t *testing.T) {
		customRulesMode = RulesAppend
		customRules = []Rule{{Name: "AhrefsBot", Action: RuleAllow, Comment: "allowed here"}}
		if k, _ := classifyUAlib(ahrefs); k != UAUnknownBot {
			t.Errorf("Ahrefs should pass via its own rule, got %s", k)
		}
	})

	t.Run("append: undescribed bots fall back to the built-in maps", func(t *testing.T) {
		customRulesMode = RulesAppend
		customRules = []Rule{{Match: "PartnerCrawler", Action: RuleAllow}}
		if k, _ := classifyUAlib(ahrefs); k != UABadBot {
			t.Errorf("Ahrefs without its own rule should stay blacklisted, got %s", k)
		}
		if k, _ := classifyUAlib(partner); k != UAUnknownBot {
			t.Errorf("partner should pass, got %s", k)
		}
	})

	t.Run("override: built-in maps are off", func(t *testing.T) {
		customRulesMode = RulesOverride
		customRules = []Rule{{Match: "PartnerCrawler", Action: RuleBlock}}
		// Ahrefs has no rule -> in override mode it is treated as a plain client
		if k, _ := classifyUAlib(ahrefs); k != UABrowser {
			t.Errorf("in override an undescribed bot should go by rate, got %s", k)
		}
		if k, _ := classifyUAlib(partner); k != UABadBot {
			t.Errorf("a rule-described bot should be blocked, got %s", k)
		}
	})

	t.Run("real browser is untouched", func(t *testing.T) {
		customRulesMode = RulesAppend
		customRules = []Rule{{Match: "PartnerCrawler", Action: RuleBlock}}
		if k, _ := classifyUAlib(chrome); k != UABrowser {
			t.Errorf("plain Chrome should stay a browser, got %s", k)
		}
	})
}
