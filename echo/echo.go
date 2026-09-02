// Package bgecho adapts botguard to Echo v4.
//
//	g, _ := botguard.New(rdb, botguard.NewConfig(p))
//	bgecho.Register(g, e)   // middleware + /__bg/* endpoints
package bgecho

import (
	"net/http"

	"github.com/hellmany/botguard"
	"github.com/labstack/echo/v4"
)

// ContextKey is the key the verdict is stored under in echo.Context.
const ContextKey = "botguard.verdict"

// VerdictFrom returns the verdict the middleware stored for this request.
func VerdictFrom(c echo.Context) (botguard.Verdict, bool) {
	v, ok := c.Get(ContextKey).(botguard.Verdict)
	return v, ok
}

// Middleware wraps the net/http core for Echo.
func Middleware(g *botguard.Guard) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var err error
			raw := c.Response().Writer
			g.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				// The core may hand back a wrapped writer (the referrer
				// shim); route Echo's writes through it. The raw writer is
				// passed in so the wrapper never wraps echo.Response itself.
				if w != raw {
					c.Response().Writer = w
				}
				if v, ok := botguard.VerdictFromRequest(r); ok {
					c.Set(ContextKey, v)
				}
				err = next(c)
			})).ServeHTTP(raw, c.Request())
			return err
		}
	}
}

func wrap(h http.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		h(c.Response(), c.Request())
		return nil
	}
}

// Register installs the middleware and every endpoint the guard needs. In
// ModeOff it installs nothing.
func Register(g *botguard.Guard, e *echo.Echo) {
	if g.Disabled() {
		return
	}
	for _, rt := range g.Routes() {
		e.Add(rt.Method, rt.Path, wrap(rt.Handler))
	}
	e.Use(Middleware(g))
}
