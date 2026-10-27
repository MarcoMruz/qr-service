package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

const testPassword = "correct horse battery staple"

func newTestHandler(t *testing.T) (http.Handler, *server) {
	t.Helper()
	cfg := config{password: testPassword, sessionSecret: strings.Repeat("s", minSecretLength)}
	srv := newServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return srv.routes(), srv
}

func do(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func loginRequest(password string) *http.Request {
	form := url.Values{"password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func qrRequestWithSession(srv *server, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/qr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	token, _ := srv.sessions.issue()
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	return req
}

func TestHomeShowsLoginWithoutSession(t *testing.T) {
	handler, _ := newTestHandler(t)
	rec := do(handler, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Fatalf("want login page, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHomeShowsAppWithSession(t *testing.T) {
	handler, srv := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	token, _ := srv.sessions.issue()
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	rec := do(handler, req)
	if !strings.Contains(rec.Body.String(), `x-data="qrMaker"`) {
		t.Fatalf("want app page, got: %s", rec.Body.String())
	}
}

func TestLoginWithCorrectPasswordSetsSecureCookie(t *testing.T) {
	handler, srv := newTestHandler(t)
	rec := do(handler, loginRequest(testPassword))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || !srv.sessions.valid(c.Value) {
		t.Fatalf("cookie is not a valid hardened session: %+v", c)
	}
}

func TestLoginWithWrongPasswordIsRejected(t *testing.T) {
	handler, _ := newTestHandler(t)
	rec := do(handler, loginRequest("nope"))

	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("want 401 without cookie, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "That password isn&#39;t right") {
		t.Fatalf("want wrong-password message, got: %s", rec.Body.String())
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	handler, _ := newTestHandler(t)
	for range 5 {
		do(handler, loginRequest("nope"))
	}
	rec := do(handler, loginRequest(testPassword))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after 5 tries, got %d", rec.Code)
	}
}

func TestQRRequiresSession(t *testing.T) {
	handler, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/qr", strings.NewReader(`{"text":"hi"}`))

	if rec := do(handler, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestQRReturnsPNG(t *testing.T) {
	handler, srv := newTestHandler(t)
	rec := do(handler, qrRequestWithSession(srv, `{"text":"https://example.com"}`))

	pngSignature := []byte("\x89PNG\r\n\x1a\n")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(rec.Body.Bytes(), pngSignature) {
		t.Fatalf("want PNG, got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestQRRejectsBadInput(t *testing.T) {
	tests := map[string]struct {
		body       string
		wantStatus int
	}{
		"empty":            {`{"text":"   "}`, http.StatusBadRequest},
		"too many chars":   {`{"text":"` + strings.Repeat("a", maxQRTextChars+1) + `"}`, http.StatusUnprocessableEntity},
		"too many bytes":   {`{"text":"` + strings.Repeat("😀", 600) + `"}`, http.StatusUnprocessableEntity},
		"invalid json":     {`{"text":`, http.StatusBadRequest},
		"oversized":        {`{"text":"` + strings.Repeat("a", maxQRBodyBytes) + `"}`, http.StatusBadRequest},
		"trailing garbage": {`{"text":"hi"}not-json`, http.StatusBadRequest},
		"second object":    {`{"text":"hi"}{"text":"different"}`, http.StatusBadRequest},
		"trailing null":    {`{"text":"hi"}null`, http.StatusBadRequest},
		"oversized suffix": {`{"text":"hi"}` + strings.Repeat(" ", maxQRBodyBytes), http.StatusBadRequest},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			handler, srv := newTestHandler(t)
			rec := do(handler, qrRequestWithSession(srv, tc.body))
			if rec.Code != tc.wantStatus || !strings.Contains(rec.Body.String(), `"error"`) {
				t.Fatalf("want %d with error JSON, got %d (%s)", tc.wantStatus, rec.Code, rec.Header().Get("Content-Type"))
			}
		})
	}
}

func TestQRIsRateLimited(t *testing.T) {
	handler, srv := newTestHandler(t)
	for range 30 {
		do(handler, qrRequestWithSession(srv, `{"text":"hi"}`))
	}
	if rec := do(handler, qrRequestWithSession(srv, `{"text":"hi"}`)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after 30 codes, got %d", rec.Code)
	}
}

func TestCrossOriginPostIsBlocked(t *testing.T) {
	handler, srv := newTestHandler(t)
	req := qrRequestWithSession(srv, `{"text":"hi"}`)
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	if rec := do(handler, req); rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestSecurityAndCrawlerHeaders(t *testing.T) {
	handler, _ := newTestHandler(t)
	rec := do(handler, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"Content-Security-Policy": contentSecurityPolicy,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"X-Robots-Tag":            "noindex, nofollow, noarchive, nosnippet, noimageindex",
		"Cache-Control":           "no-store",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if !strings.Contains(rec.Body.String(), `<meta name="robots" content="noindex`) {
		t.Error("page is missing the robots meta tag")
	}
}

func TestRobotsDisallowsEverything(t *testing.T) {
	handler, _ := newTestHandler(t)
	rec := do(handler, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))

	if rec.Body.String() != "User-agent: *\nDisallow: /\n" {
		t.Fatalf("unexpected robots.txt: %q", rec.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	handler, _ := newTestHandler(t)
	if rec := do(handler, httptest.NewRequest(http.MethodGet, "/healthz", nil)); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestStaticServesFilesButNotListings(t *testing.T) {
	handler, _ := newTestHandler(t)

	rec := do(handler, httptest.NewRequest(http.MethodGet, "/static/app.js", nil))
	etag := rec.Header().Get("ETag")
	if rec.Code != http.StatusOK || etag == "" {
		t.Fatalf("want app.js with ETag, got %d %q", rec.Code, etag)
	}

	revalidate := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	revalidate.Header.Set("If-None-Match", etag)
	if rec := do(handler, revalidate); rec.Code != http.StatusNotModified {
		t.Fatalf("want 304 for unchanged file, got %d", rec.Code)
	}
	if rec := do(handler, httptest.NewRequest(http.MethodGet, "/static/", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("want directory listing hidden, got %d", rec.Code)
	}
}

func TestClientIPUsesLastForwardedHopOnlyWhenTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")

	if got := (&server{trustProxy: true}).clientIP(req); got != "203.0.113.7" {
		t.Errorf("trusted proxy: got %q", got)
	}
	if got := (&server{trustProxy: false}).clientIP(req); got != "10.0.0.1" {
		t.Errorf("untrusted proxy: got %q", got)
	}
}

func TestLoginIsLimitedGloballyAcrossIPs(t *testing.T) {
	handler, _ := newTestHandler(t)
	for i := range 30 {
		req := loginRequest("nope")
		req.RemoteAddr = "198.51.100." + strconv.Itoa(i) + ":1234"
		do(handler, req)
	}
	req := loginRequest(testPassword)
	req.RemoteAddr = "198.51.100.200:1234"
	if rec := do(handler, req); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 once global budget is spent, got %d", rec.Code)
	}
}

func TestQRAcceptsTrailingWhitespace(t *testing.T) {
	handler, srv := newTestHandler(t)
	if rec := do(handler, qrRequestWithSession(srv, "{\"text\":\"hi\"}\n\t ")); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestLogsExcludeClientData(t *testing.T) {
	var logs bytes.Buffer
	srv := newServer(config{password: testPassword, sessionSecret: testSecret, trustProxy: true}, slog.New(slog.NewJSONHandler(&logs, nil)))
	handler := srv.routes()
	requests := []*http.Request{
		loginRequest("private-password-marker"),
		qrRequestWithSession(srv, `{"text":"private-text-marker"}broken`),
		loginRequest("wrong"),
	}
	requests[2].URL.Path = "/private-path-marker"
	requests[2].Header.Set("Sec-Fetch-Site", "cross-site")
	requests[2].Header.Set("Origin", "https://private-origin-marker.example")
	for _, req := range requests {
		req.RemoteAddr = "203.0.113.77:1234"
		req.Header.Set("X-Forwarded-For", "198.51.100.99")
		do(handler, req)
	}
	if logs.Len() == 0 {
		t.Fatal("expected failure logs")
	}
	for _, private := range []string{"203.0.113.77", "198.51.100.99", "private-password-marker", "private-text-marker", "private-path-marker", "private-origin-marker"} {
		if strings.Contains(logs.String(), private) {
			t.Errorf("logs contain %q", private)
		}
	}
}

type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header { return w.header }
func (w *failingResponseWriter) WriteHeader(int)     {}
func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken pipe: private-error-marker")
}

func TestResponseWriteFailuresAreLogged(t *testing.T) {
	for _, target := range []string{"/", "/api/qr", "/healthz", "/static/app.js", "/unauthorized"} {
		t.Run(target, func(t *testing.T) {
			var logs bytes.Buffer
			srv := newServer(config{password: testPassword, sessionSecret: testSecret}, slog.New(slog.NewJSONHandler(&logs, nil)))
			req := httptest.NewRequest(http.MethodGet, target, nil)
			if target == "/api/qr" {
				req = qrRequestWithSession(srv, `{"text":"private-text-marker"}`)
			}
			if target == "/unauthorized" {
				req = httptest.NewRequest(http.MethodPost, "/api/qr", strings.NewReader(`{"text":"private-text-marker"}`))
			}
			srv.routes().ServeHTTP(&failingResponseWriter{header: make(http.Header)}, req)
			var entry map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
				t.Fatalf("want one JSON log, got %q: %v", logs.String(), err)
			}
			if entry["error_category"] != "response_write_failed" || strings.Contains(logs.String(), "private-") {
				t.Fatalf("unexpected delivery failure log: %s", logs.String())
			}
		})
	}
}

func TestPanicRecoveryDoesNotLogPayload(t *testing.T) {
	var logs bytes.Buffer
	srv := newServer(config{password: testPassword, sessionSecret: testSecret}, slog.New(slog.NewJSONHandler(&logs, nil)))
	handler := srv.logFailures(srv.recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("private-panic-marker")
	})))
	rec := do(handler, httptest.NewRequest(http.MethodGet, "/private-path-marker", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(logs.String(), "panic recovered") {
		t.Fatalf("want recovered 500, got %d and logs %q", rec.Code, logs.String())
	}
	if strings.Contains(logs.String(), "private-") || strings.Contains(rec.Body.String(), "private-") {
		t.Fatal("panic details leaked")
	}
}

func TestStatusRecorderKeepsFirstFinalStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	writer := &statusRecorder{ResponseWriter: rec}
	writer.WriteHeader(http.StatusUnauthorized)
	writer.WriteHeader(http.StatusInternalServerError)
	if writer.status != http.StatusUnauthorized || rec.Code != http.StatusUnauthorized {
		t.Fatalf("recorded status %d differs from first final status", writer.status)
	}
}

func TestQRHandlesInjectionPayloadsAsData(t *testing.T) {
	for _, text := range []string{
		`<script>alert(document.cookie)</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(1)`,
		`'; DROP TABLE users; --`,
		`$(cat /etc/passwd) {{.password}} ../../../etc/passwd`,
	} {
		handler, srv := newTestHandler(t)
		body, err := json.Marshal(qrRequest{Text: text})
		if err != nil {
			t.Fatal(err)
		}
		rec := do(handler, qrRequestWithSession(srv, string(body)))
		want, err := generateQR(text)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" || !bytes.Equal(rec.Body.Bytes(), want) {
			t.Fatalf("payload was not returned solely as a PNG: %q", text)
		}
	}
}
