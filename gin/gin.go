// Package bggin adapts botguard to Gin.
//
//	g, _ := botguard.New(rdb, botguard.NewConfig(p))
//	bggin.Register(g, r)   // middleware + /__bg/* endpoints
package bggin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hellmany/botguard"
)

// ContextKey is the key the verdict is stored under in gin.Context.
const ContextKey = "botguard.verdict"

// VerdictFrom returns the verdict the middleware stored for this request.
func VerdictFrom(c *gin.Context) (botguard.Verdict, bool) {
	v, ok := c.Get(ContextKey)
	if !ok {
		return botguard.Verdict{}, false
	}
	vv, ok := v.(botguard.Verdict)
	return vv, ok
}

// wrapped routes Gin's writes through the writer the core handed back (the
// referrer shim) while keeping Gin's status bookkeeping on the original.
type wrapped struct {
	gin.ResponseWriter
	w http.ResponseWriter
}

func (x *wrapped) Header() http.Header               { return x.w.Header() }
func (x *wrapped) Write(b []byte) (int, error)       { return x.w.Write(b) }
func (x *wrapped) WriteString(s string) (int, error) { return x.w.Write([]byte(s)) }
func (x *wrapped) WriteHeader(code int)              { x.w.WriteHeader(code) }

// Middleware wraps the net/http core for Gin.
func Middleware(g *botguard.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		orig := c.Writer
		g.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			passed = true
			c.Request = r
			if w != http.ResponseWriter(orig) {
				c.Writer = &wrapped{ResponseWriter: orig, w: w}
			}
			if v, ok := botguard.VerdictFromRequest(r); ok {
				c.Set(ContextKey, v)
			}
			c.Next()
		})).ServeHTTP(orig, c.Request)
		if !passed {
			c.Abort() // the core already wrote the challenge or denial
		}
	}
}

// Register installs the middleware and every endpoint the guard needs. In
// ModeOff it installs nothing.
func Register(g *botguard.Guard, r gin.IRouter) {
	if g.Disabled() {
		return
	}
	for _, rt := range g.Routes() {
		r.Handle(rt.Method, rt.Path, gin.WrapF(rt.Handler))
	}
	r.Use(Middleware(g))
}
