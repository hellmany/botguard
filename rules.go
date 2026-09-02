// Custom bot rules. The built-in maps cover the common case, but every
// project has its own specifics: internal monitoring, a partner crawler to
// allow, or a scraper that targets you in particular. Rules from
// Params.Rules are checked first and override the built-in lists.
package botguard

import "strings"

// RuleAction decides what happens to a client matched by a rule.
type RuleAction string

const (
	RuleAllow     RuleAction = "allow"     // pass, skipping the score
	RuleBlock     RuleAction = "block"     // 403
	RuleChallenge RuleAction = "challenge" // proof-of-work or checkbox, by score
	RuleScore     RuleAction = "score"     // normal path: rates and behaviour
	// RuleKnownBot treats the client as a known bot and verifies its ASN:
	// own network passes, a foreign one is an impostor.
	RuleKnownBot RuleAction = "known_bot"
)

// Rule matches either a case-insensitive User-Agent substring or the exact
// name returned by the UA parser.
type Rule struct {
	// Match is a UA substring. Leave empty when matching by Name.
	Match string
	// Name is the exact bot name from mileusna (Googlebot, AhrefsBot).
	Name string
	// Action defaults to RuleScore when empty.
	Action RuleAction
	// BotName is the name recorded in statistics; defaults to Name or Match.
	BotName string
	// ASNs lists the bot's official networks for Action=known_bot. An empty
	// list skips the ASN check and simply passes the bot.
	ASNs []uint32
	// Comment documents the rule; it does not affect logic.
	Comment string
}

// RulesMode controls how custom rules relate to the built-in maps.
type RulesMode string

const (
	// RulesAppend extends the built-in maps: custom rules are checked first,
	// anything unmatched falls through to the standard lists.
	RulesAppend RulesMode = "append"
	// RulesOverride replaces the built-in maps entirely: anything unmatched
	// goes through rate limiting only. For projects with their own policy.
	RulesOverride RulesMode = "override"
)

// matchRules returns the first matching rule, or nil to fall through to the
// built-in maps.
func matchRules(rules []Rule, ua, parsedName string) *Rule {
	if len(rules) == 0 {
		return nil
	}
	l := strings.ToLower(ua)
	for i := range rules {
		r := &rules[i]
		if r.Name != "" && r.Name == parsedName {
			return r
		}
		if r.Match != "" && strings.Contains(l, strings.ToLower(r.Match)) {
			return r
		}
	}
	return nil
}

// kindOf maps a rule action onto the UA kind the engine understands.
func (r *Rule) kindOf() (UAKind, string) {
	name := r.BotName
	if name == "" {
		if r.Name != "" {
			name = r.Name
		} else {
			name = r.Match
		}
	}
	switch r.Action {
	case RuleAllow:
		// Passed as a declared bot: skips scoring but still recorded.
		return UAUnknownBot, name
	case RuleBlock:
		return UABadBot, name
	case RuleChallenge:
		return UAToolAgent, name
	case RuleKnownBot:
		return UAKnownBot, name
	default:
		// RuleScore and empty action: the normal rate-based path.
		return UABrowser, ""
	}
}
