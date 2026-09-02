package botguard

import "testing"

// safeDest keeps same-site paths and rejects external and /__bg/ targets.
func TestSafeDest(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"relative path", "/post/123/onlyfans/user", "/post/123/onlyfans/user"},
		{"with query", "/search?q=test&page=2", "/search?q=test&page=2"},
		{"absolute same site", "https://example.com/post/1", "/post/1"},
		{"empty", "", ""},
		{"external host", "https://evil.com/steal", "/steal"},
		{"protocol relative", "//evil.com/steal", ""},
		{"no leading slash", "post/1", ""},
		{"challenge page itself", "/__bg/captcha", ""},
		{"stats page", "/__bg/stats", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := safeDest(c.in); got != c.want {
				t.Errorf("safeDest(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
