package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	maxLoginBodyBytes = 1 << 10
	maxQRBodyBytes    = 16 << 10

	msgGeneric       = "Something went wrong. Please try again."
	msgWrongPassword = "That password isn't right. Check it and try again."
	msgTooManyLogins = "Too many tries. Wait a minute, then try again."
	msgTooManyCodes  = "Too many codes in a short time. Wait a minute, then try again."
	msgEmptyText     = "Paste a link or some text first."
	msgTextTooLong   = "That's too long for a QR code. Try a shorter link or text."
	msgSessionEnded  = "Your session ended. Reload the page to sign in again."
)

const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' blob:; connect-src 'self'; form-action 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'"

type server struct {
	log                *slog.Logger
	sessions           *sessions
	loginLimiter       *rateLimiter
	globalLoginLimiter *rateLimiter
	qrLimiter          *rateLimiter
	trustProxy         bool
	pages              *template.Template
}

type loginPage struct {
	Error string
}

func newServer(cfg config, logger *slog.Logger) *server {
	return &server{
		log:          logger,
		sessions:     newSessions(cfg.sessionSecret, cfg.password),
		loginLimiter: newRateLimiter(5, time.Minute),
		// Caps total password guesses, since attackers can rotate IPs faster than per-IP limits react.
		globalLoginLimiter: newRateLimiter(30, time.Minute),
		qrLimiter:          newRateLimiter(30, time.Minute),
		trustProxy:         cfg.trustProxy,
		pages:              template.Must(template.ParseFS(webFS, "web/*.html")),
	}
}

func (s *server) routes() http.Handler {
	static, err := fs.Sub(webFS, "web/static")
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /api/qr", s.requireSession(s.handleQR))
	mux.HandleFunc("GET /robots.txt", handleRobots)
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.Handle("GET /static/", http.StripPrefix("/static/", serveStatic(static)))

	csrf := http.NewCrossOriginProtection()
	csrf.SetDenyHandler(http.HandlerFunc(s.handleCrossOrigin))

	return s.logFailures(s.recoverPanics(securityHeaders(csrf.Handler(mux))))
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	if s.hasSession(r) {
		s.render(w, http.StatusOK, "app.html", nil)
		return
	}
	s.render(w, http.StatusOK, "login.html", loginPage{})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginLimiter.allow(rateLimitKey(ip)) || !s.globalLoginLimiter.allow("all") {
		s.log.Warn("login rate limited", "source", "handleLogin", "outcome", "login page shown with wait message")
		s.render(w, http.StatusTooManyRequests, "login.html", loginPage{Error: msgTooManyLogins})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	if err := r.ParseForm(); err != nil {
		s.log.Warn("login form unreadable", "source", "handleLogin", "error_category", bodyErrorCategory(err))
		s.render(w, http.StatusBadRequest, "login.html", loginPage{Error: msgGeneric})
		return
	}
	if !s.sessions.checkPassword(r.PostFormValue("password")) {
		s.log.Warn("login failed", "source", "handleLogin", "outcome", "wrong password message shown")
		s.render(w, http.StatusUnauthorized, "login.html", loginPage{Error: msgWrongPassword})
		return
	}

	token, expires := s.sessions.issue()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type qrRequest struct {
	Text string `json:"text"`
}

func (s *server) handleQR(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.qrLimiter.allow(rateLimitKey(ip)) {
		s.log.Warn("qr rate limited", "source", "handleQR", "outcome", "wait message shown")
		writeJSONError(w, http.StatusTooManyRequests, msgTooManyCodes)
		return
	}

	var req qrRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxQRBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		s.log.Warn("qr request unreadable", "source", "handleQR", "error_category", bodyErrorCategory(err))
		writeJSONError(w, http.StatusBadRequest, msgGeneric)
		return
	}

	text := strings.TrimSpace(req.Text)
	png, err := generateQR(text)
	switch {
	case errors.Is(err, errEmptyText):
		writeJSONError(w, http.StatusBadRequest, msgEmptyText)
	case errors.Is(err, errTextTooLong):
		writeJSONError(w, http.StatusUnprocessableEntity, msgTextTooLong)
	case err != nil:
		s.log.Error("qr encode failed", "source", "handleQR", "text_bytes", len(text), "error", err.Error(), "outcome", "generic error shown")
		writeJSONError(w, http.StatusInternalServerError, msgGeneric)
	default:
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	}
}

func (s *server) handleCrossOrigin(w http.ResponseWriter, r *http.Request) {
	s.log.Warn("cross-origin request blocked", "source", "CrossOriginProtection", "outcome", "403 shown")
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func handleRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok"))
}

func (s *server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hasSession(r) {
			writeJSONError(w, http.StatusUnauthorized, msgSessionEnded)
			return
		}
		next(w, r)
	}
}

func (s *server) hasSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	return err == nil && s.sessions.valid(cookie.Value)
}

// clientIP uses the last X-Forwarded-For hop only behind a trusted proxy, because clients can forge earlier hops.
func (s *server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if forwarded := r.Header.Values("X-Forwarded-For"); len(forwarded) > 0 {
			hops := strings.Split(forwarded[len(forwarded)-1], ",")
			if ip := strings.TrimSpace(hops[len(hops)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// render buffers the page so a template error never sends a half-written response.
func (s *server) render(w http.ResponseWriter, status int, page string, data any) {
	var buf bytes.Buffer
	if err := s.pages.ExecuteTemplate(&buf, page, data); err != nil {
		s.log.Error("template render failed", "source", "render", "page", page, "error", err.Error(), "outcome", "500 shown")
		http.Error(w, msgGeneric, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// bodyErrorCategory avoids logging parser messages, which can quote fragments of the submitted body.
func bodyErrorCategory(err error) string {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return "body_too_large"
	}
	return "malformed_body"
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// serveStatic revalidates every load against a content-hash ETag, so a deploy is picked up immediately
// while unchanged files still answer 304.
func serveStatic(files fs.FS) http.Handler {
	etags := hashFiles(files)
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag, ok := etags[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", etag)
		fileServer.ServeHTTP(w, r)
	})
}

func hashFiles(files fs.FS) map[string]string {
	etags := make(map[string]string)
	err := fs.WalkDir(files, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := fs.ReadFile(files, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		etags[path] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})
	if err != nil {
		panic(err)
	}
	return etags
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	writeFailed bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	if status >= 200 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(data)
	if err != nil || n != len(data) {
		r.writeFailed = true
	}
	return n, err
}

// Expected client errors are logged where they happen.
func (s *server) logFailures(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.writeFailed {
			s.log.Warn("response delivery failed", "source", "logFailures", "route", r.Pattern,
				"status", recorder.status, "duration_ms", time.Since(start).Milliseconds(),
				"error_category", "response_write_failed", "outcome", "response may be incomplete")
		} else if recorder.status >= http.StatusInternalServerError {
			s.log.Error("request failed", "source", "logFailures", "route", r.Pattern,
				"status", recorder.status, "duration_ms", time.Since(start).Milliseconds())
		}
	})
}

func (s *server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				s.log.Error("panic recovered", "source", "recoverPanics", "route", r.Pattern, "outcome", "500 shown")
				http.Error(w, msgGeneric, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
