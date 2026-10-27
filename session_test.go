package main

import (
	"strings"
	"testing"
	"time"
)

var testSecret = strings.Repeat("s", minSecretLength)

func TestSessionRoundTrip(t *testing.T) {
	s := newSessions(testSecret, "pw")
	token, _ := s.issue()
	if !s.valid(token) {
		t.Fatal("freshly issued token should be valid")
	}
}

func TestSessionRejectsTamperedOrMalformedTokens(t *testing.T) {
	s := newSessions(testSecret, "pw")
	token, _ := s.issue()
	payload, signature, _ := strings.Cut(token, ".")

	for _, bad := range []string{"", "garbage", payload, "9999999999." + signature, payload + ".x" + signature} {
		if s.valid(bad) {
			t.Errorf("token %q should be invalid", bad)
		}
	}
}

func TestSessionExpires(t *testing.T) {
	s := newSessions(testSecret, "pw")
	token, _ := s.issue()
	s.now = func() time.Time { return time.Now().Add(sessionTTL + time.Second) }

	if s.valid(token) {
		t.Fatal("expired token should be invalid")
	}
}

func TestPasswordChangeInvalidatesSessions(t *testing.T) {
	token, _ := newSessions(testSecret, "old").issue()
	if newSessions(testSecret, "new").valid(token) {
		t.Fatal("token from the old password should be invalid")
	}
}

func TestCheckPassword(t *testing.T) {
	s := newSessions(testSecret, "pw")
	if !s.checkPassword("pw") || s.checkPassword("PW") || s.checkPassword("") {
		t.Fatal("checkPassword must match exactly")
	}
}
