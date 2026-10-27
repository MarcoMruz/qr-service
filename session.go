package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookieName = "qr_session"
	sessionTTL        = 30 * 24 * time.Hour
)

// sessions issues and verifies stateless, HMAC-signed session tokens.
// The signing key is derived from the password too, so changing APP_PASSWORD logs everyone out.
type sessions struct {
	key          []byte
	passwordHash [32]byte
	now          func() time.Time
}

func newSessions(secret, password string) *sessions {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(password))
	return &sessions{
		key:          mac.Sum(nil),
		passwordHash: sha256.Sum256([]byte(password)),
		now:          time.Now,
	}
}

// checkPassword compares fixed-length hashes so timing reveals neither content nor length.
func (s *sessions) checkPassword(candidate string) bool {
	candidateHash := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(candidateHash[:], s.passwordHash[:]) == 1
}

func (s *sessions) issue() (token string, expires time.Time) {
	expires = s.now().Add(sessionTTL)
	payload := strconv.FormatInt(expires.Unix(), 10)
	return payload + "." + s.sign(payload), expires
}

func (s *sessions) valid(token string) bool {
	payload, signature, found := strings.Cut(token, ".")
	if !found || !hmac.Equal([]byte(signature), []byte(s.sign(payload))) {
		return false
	}
	expiresUnix, err := strconv.ParseInt(payload, 10, 64)
	return err == nil && s.now().Unix() < expiresUnix
}

func (s *sessions) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
