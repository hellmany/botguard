// Package bgfiber adapts botguard to Fiber v2.
//
//	g, _ := botguard.New(rdb, botguard.NewConfig(p))
//	bgfiber.Register(g, app)   // middleware + /__bg/* endpoints
//
// Fiber writes to fasthttp directly, past any net/http writer, so the adapter
// runs the core against a recorder and copies the outcome into the Fiber
// response: a challenge or denial is sent as is, a pass carries the headers
// on and the referrer shim is injected into the HTML after the handler ran.
package bgfiber

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/hellmany/botguard"
)

// LocalsKey is the key the verdict is stored under in c.Locals.
const LocalsKey = "botguard.verdict"

// VerdictFrom returns the verdict the middleware stored for this request.
func VerdictFrom(c *fiber.Ctx) (botguard.Verdict, bool) {
	v, ok := c.Locals(LocalsKey).(botguard.Verdict)
	return v, ok
}

type recorder struct {
	hdr    http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header         { return r.hdr }
func (r *recorder) WriteHeader(code int)        { r.status = code }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }

// Middleware runs the net/http core for Fiber.
func Middleware(g *botguard.Guard) fiber.Handler {
	return func(c *fiber.Ctx) error {
		r, err := adaptor.ConvertRequest(c, true)
		if err != nil {
			return c.Next()
		}
		rec := &recorder{hdr: http.Header{}, status: http.StatusOK}
		passed := false
		var shim []byte
		g.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r2 *http.Request) {
			passed = true
			if v, ok := botguard.VerdictFromRequest(r2); ok {
				c.Locals(LocalsKey, v)
			}
			// Restored referrer goes to the handler.
			if ref := r2.Header.Get("Referer"); ref != "" {
				c.Request().Header.Set("Referer", ref)
			} else {
				c.Request().Header.Del("Referer")
			}
			shim, _ = botguard.ShimFor(w)
		})).ServeHTTP(rec, r)

		copyHeaders(c, rec.hdr)
		if !passed {
			c.Status(rec.status)
			return c.Send(rec.body.Bytes())
		}
		err = c.Next()
		if shim != nil && c.Response().StatusCode() == http.StatusOK &&
			strings.HasPrefix(string(c.Response().Header.ContentType()), "text/html") &&
			len(c.Response().Header.Peek("Content-Encoding")) == 0 {
			c.Response().SetBody(botguard.InjectShim(c.Response().Body(), shim))
		}
		return err
	}
}

func copyHeaders(c *fiber.Ctx, h http.Header) {
	for k, vs := range h {
		for _, v := range vs {
			c.Response().Header.Add(k, v)
		}
	}
}

// Register installs the middleware and every endpoint the guard needs. In
// ModeOff it installs nothing.
func Register(g *botguard.Guard, app fiber.Router) {
	if g.Disabled() {
		return
	}
	for _, rt := range g.Routes() {
		app.Add(rt.Method, rt.Path, adaptor.HTTPHandlerFunc(rt.Handler))
	}
	app.Use(Middleware(g))
}
