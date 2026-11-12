package mcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mutex-solutions/arco/internal/auth"
	"github.com/mutex-solutions/arco/internal/herdr"
	"github.com/mutex-solutions/arco/internal/registry"
)

// MaxHTTPBodyBytes caps one JSON-RPC request body. The largest legitimate call
// is a 64 KiB send_text payload; 4 MiB leaves room for JSON escaping.
const MaxHTTPBodyBytes = 4 << 20

// HTTPOptions configures the token-authenticated Streamable HTTP endpoint.
type HTTPOptions struct {
	Registry *registry.Registry // full registry; each token sees a filtered view
	Client   *herdr.Client      // shared, built from the full registry
	Tokens   *auth.Store
	Version  string
	Log      io.Writer // request log (method, status, duration, token id); nil → discard
}

type tokenKey struct{}

// NewHTTPHandler serves MCP at POST /mcp and a liveness probe at GET /healthz.
//
// Every /mcp request carries its own bearer token and is authenticated before
// any tool work. The transport is stateless, so there is no session to trust.
// Each token gets an MCP server built from the registry filtered to its
// machines, with the mutating tools omitted for read tokens. Everything else
// is 404; there is no OAuth discovery metadata.
func NewHTTPHandler(o HTTPOptions) http.Handler {
	logOut := o.Log
	if logOut == nil {
		logOut = io.Discard
	}
	reqLog := slog.New(slog.NewTextHandler(logOut, nil))

	// Scoped servers are cached by everything that shapes them, so a token
	// file edited by hand never keeps a wider server alive.
	var mu sync.Mutex
	servers := make(map[string]*sdkmcp.Server)
	serverFor := func(rec auth.Record) *sdkmcp.Server {
		key := rec.ID + "|" + rec.Hash + "|" + rec.Scope + "|" + strings.Join(rec.Machines, ",")
		mu.Lock()
		defer mu.Unlock()
		if s, ok := servers[key]; ok {
			return s
		}
		s := NewScopedMCPServer(o.Registry.Filter(rec.Machines), o.Client, o.Version, rec.ReadOnly())
		servers[key] = s
		return s
	}

	mcpHandler := sdkmcp.NewStreamableHTTPHandler(func(r *http.Request) *sdkmcp.Server {
		rec, ok := r.Context().Value(tokenKey{}).(auth.Record)
		if !ok {
			return nil // unreachable: requireToken runs first
		}
		return serverFor(rec)
	}, &sdkmcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true,
		MaxRequestBodyBytes: MaxHTTPBodyBytes,
		Logger:              newScrubbingLogger(logOut),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle("/mcp", requireToken(o.Tokens, reqLog, normalizeAccept(mcpHandler)))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	return logRequests(reqLog, securityHeaders(mux))
}

// requireToken authenticates every request. All failures look the same: 401
// with a bare Bearer challenge and no hint of why.
// A broken token file also answers 401 (fail closed), but is logged so the
// operator can see why every client is rejected.
func requireToken(store *auth.Store, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			unauthorized(w)
			return
		}
		rec, err := store.Authenticate(raw)
		if err != nil {
			if !errors.Is(err, auth.ErrUnauthorized) {
				log.Error("token store unavailable", "error", err.Error())
			}
			unauthorized(w)
			return
		}
		if lw, ok := w.(*loggingWriter); ok {
			lw.tokenID = rec.ID
		}
		ctx := WithAudit(context.WithValue(r.Context(), tokenKey{}, rec), log, rec.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(h string) (string, bool) {
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}

// Connection: close stops the server from draining an unread body, which a
// client without a token could otherwise trickle in to hold the connection.
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	w.Header().Set("WWW-Authenticate", `Bearer realm="arco"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":"unauthorized"}`+"\n")
}

// normalizeAccept fills in the Accept header the Streamable HTTP transport
// requires; some clients (Gemini CLI among them) omit part of it.
func normalizeAccept(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			a := r.Header.Get("Accept")
			if !strings.Contains(a, "application/json") || !strings.Contains(a, "text/event-stream") {
				r.Header.Set("Accept", "application/json, text/event-stream")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

type loggingWriter struct {
	http.ResponseWriter
	status  int
	tokenID string
}

func (w *loggingWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *loggingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *loggingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests records method, path, status, duration, and token id. Never the
// Authorization header, query string, or body.
func logRequests(l *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingWriter{ResponseWriter: w}
		next.ServeHTTP(lw, r)
		token := lw.tokenID
		if token == "" {
			token = "-"
		}
		// Unknown paths are not echoed: a client that put a token in the URL
		// would otherwise write it to the log.
		path := r.URL.Path
		if path != "/mcp" && path != "/healthz" {
			path = "other"
		}
		l.Info("request", "method", r.Method, "path", path, "status", lw.status,
			"duration", time.Since(start).Round(time.Millisecond), "token", token)
	})
}

// NewHTTPServer wraps h with conservative timeouts. ReadTimeout bounds the
// request read, including the body. There is no WriteTimeout: a prompt_agent
// call may legitimately block for up to two minutes.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}
