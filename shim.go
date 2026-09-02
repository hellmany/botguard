package botguard

import "net/http"

// ShimFor returns the document.referrer shim the core attached to w, if any.
// Adapters whose framework writes past the net/http writer (Fiber) use it to
// inject the shim themselves.
func ShimFor(w http.ResponseWriter) ([]byte, bool) {
	if i, ok := w.(*refInjector); ok {
		return i.shim, true
	}
	return nil, false
}

// InjectShim inserts shim right after the opening <head> tag. The body comes
// back unchanged when there is no <head> in it.
func InjectShim(body, shim []byte) []byte {
	at := headInsertPoint(body)
	if at < 0 {
		return body
	}
	out := make([]byte, 0, len(body)+len(shim))
	out = append(out, body[:at]...)
	out = append(out, shim...)
	out = append(out, body[at:]...)
	return out
}
