package botguard

import "testing"

// Mobile clients pass: no mouse, narrow screen, no plugins.
func TestCheckboxMobilePasses(t *testing.T) {
	cases := []struct {
		name string
		env  checkboxEnv
		want string // "" = let through
	}{
		{"iphone", checkboxEnv{Moved: true, DwellMS: 900, ScreenW: 390, ScreenH: 844,
			Touch: 5, Cores: 6, UAPlat: "iPhone", Plugins: 0}, ""},
		{"old android 320px", checkboxEnv{Moved: true, DwellMS: 1200, ScreenW: 320,
			ScreenH: 568, Touch: 5, Cores: 4, UAPlat: "Linux armv8l"}, ""},
		{"mobile without mouse movement", checkboxEnv{Moved: false, DwellMS: 800,
			ScreenW: 412, ScreenH: 915, Touch: 5, Cores: 8, UAPlat: "Linux aarch64"}, ""},
		{"windows tablet with touch", checkboxEnv{Moved: true, DwellMS: 700, ScreenW: 1280,
			ScreenH: 800, Touch: 10, Cores: 4, UAPlat: "Win32"}, ""},
		{"plain desktop", checkboxEnv{Moved: true, DwellMS: 1500, ScreenW: 1920,
			ScreenH: 1080, Cores: 12, UAPlat: "Win32", Plugins: 5}, ""},
		// rejected
		{"webdriver", checkboxEnv{Webdriver: true, DwellMS: 900, ScreenW: 1920, ScreenH: 1080}, "webdriver"},
		{"puppeteer", checkboxEnv{Automation: "__puppeteer", DwellMS: 900, ScreenW: 1920, ScreenH: 1080}, "automation:__puppeteer"},
		{"instant click", checkboxEnv{DwellMS: 50, ScreenW: 1920, ScreenH: 1080}, "too fast"},
		{"headless without a screen", checkboxEnv{DwellMS: 900, ScreenW: 0, ScreenH: 0}, "bad screen"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.env.suspicious()
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
