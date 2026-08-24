package concentrator

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The observability endpoint. Small on purpose: a JSON API and one
// self-contained page, no build step, no dependencies, nothing to keep in sync
// with a frontend.
//
// Auth is a single shared secret. That is proportionate: the thing it guards is
// read-only operational state on an operator's own box. It is compared in
// constant time and accepted three ways so that curl, a browser and a script
// are all easy.

// HTTPConfig configures the observability server.
type HTTPConfig struct {
	// Addr is where to listen, e.g. "127.0.0.1:10099". Empty disables it.
	//
	// Loopback by default is deliberate: the ICG ports already have to be
	// exposed for a device to reach them, and adding a second public surface
	// should be a decision, not an accident. Reach it over an ssh tunnel:
	//   ssh -N -L 10099:127.0.0.1:10099 user@server
	Addr string

	// Key is the shared secret. If empty, one is generated and returned by
	// NewHTTP so the caller can print it.
	Key string
}

// HTTPServer serves the API and UI for a Server.
type HTTPServer struct {
	srv  *Server
	key  string
	addr string

	// ln is written by Serve and read by Addr from whatever goroutine the
	// caller happens to be on, so it is guarded. ready lets a caller wait for
	// the bind instead of polling, which matters when Addr was ":0".
	mu        sync.Mutex
	ln        net.Listener
	ready     chan struct{}
	readyOnce sync.Once
}

// GeneratedKey reports the secret in use, which the caller should print if it
// generated one.
func (h *HTTPServer) GeneratedKey() string { return h.key }

// Ready is closed once the listener is bound.
func (h *HTTPServer) Ready() <-chan struct{} { return h.ready }

// Addr reports the bound address once Serve has bound, else the requested one.
func (h *HTTPServer) Addr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ln != nil {
		return h.ln.Addr().String()
	}
	return h.addr
}

// NewHTTP prepares the observability server. Nothing is bound until Serve.
func NewHTTP(srv *Server, cfg HTTPConfig) (*HTTPServer, error) {
	if cfg.Addr == "" {
		return nil, nil
	}
	key := strings.TrimSpace(cfg.Key)
	if key == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("icg: generating an API key: %w", err)
		}
		key = base64.RawURLEncoding.EncodeToString(b)
	}
	return &HTTPServer{srv: srv, key: key, addr: cfg.Addr, ready: make(chan struct{})}, nil
}

// Serve binds and serves until ctx-driven shutdown via Close.
func (h *HTTPServer) Serve() error {
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("icg: listen http %s: %w", h.addr, err)
	}
	h.mu.Lock()
	h.ln = ln
	h.mu.Unlock()
	h.readyOnce.Do(func() { close(h.ready) })

	mux := http.NewServeMux()
	// The page itself carries no data, so it is served unauthenticated; every
	// API call below it is not.
	mux.HandleFunc("/", h.handleUI)
	mux.HandleFunc("/api/status", h.auth(h.handleStatus))
	mux.HandleFunc("/api/sessions", h.auth(h.handleSessions))
	mux.HandleFunc("/api/notices", h.auth(h.handleNotices))
	mux.HandleFunc("/api/whoami", h.auth(h.handleWhoami))

	s := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	err = s.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the listener.
func (h *HTTPServer) Close() {
	h.mu.Lock()
	ln := h.ln
	h.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// auth accepts the secret as an Authorization bearer token, an X-Icgd-Key
// header, or a key query parameter. The query form exists because it makes the
// API usable from a browser address bar and from the page's own fetch calls.
func (h *HTTPServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Icgd-Key")
		if got == "" {
			if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
				got = b
			}
		}
		if got == "" {
			got = r.URL.Query().Get("key")
		}
		// Constant time, and length-independent: compare digests of equal size.
		if subtle.ConstantTimeCompare([]byte(got), []byte(h.key)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="icgd"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (h *HTTPServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.srv.Snapshot())
}

func (h *HTTPServer) handleSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.srv.Snapshot().Sessions)
}

func (h *HTTPServer) handleNotices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.srv.Notices())
}

func (h *HTTPServer) handleWhoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"ok": "1"})
}

func (h *HTTPServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// No external references at all: this has to work on a box with no
	// internet access, which is a plausible place to run a concentrator.
	_, _ = w.Write([]byte(uiHTML))
}
