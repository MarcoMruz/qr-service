package main

import (
	"strconv"
	"testing"
	"time"
)

func TestRateLimiterBlocksOverLimitAndResetsAfterWindow(t *testing.T) {
	now := time.Unix(0, 0)
	l := newRateLimiter(2, time.Minute)
	l.now = func() time.Time { return now }

	if !l.allow("a") || !l.allow("a") {
		t.Fatal("first two requests should pass")
	}
	if l.allow("a") {
		t.Fatal("third request in the window should be blocked")
	}
	if !l.allow("b") {
		t.Fatal("other clients have their own budget")
	}

	now = now.Add(time.Minute)
	if !l.allow("a") {
		t.Fatal("budget should reset after the window")
	}
}

func TestRateLimiterSweepsStaleClients(t *testing.T) {
	now := time.Unix(0, 0)
	l := newRateLimiter(1, time.Minute)
	l.now = func() time.Time { return now }

	l.allow("a")
	now = now.Add(2 * time.Minute)
	l.allow("b")

	if _, ok := l.windows["a"]; ok || len(l.windows) != 1 {
		t.Fatalf("stale client should be swept, have %d entries", len(l.windows))
	}
}

func TestRateLimiterRefusesNewClientsWhenFull(t *testing.T) {
	l := newRateLimiter(1, time.Minute)
	for i := range maxTrackedClients {
		l.allow(strconv.Itoa(i))
	}
	if l.allow("one-too-many") {
		t.Fatal("new client should be refused once the table is full")
	}
}

func TestRateLimitKeyGroupsIPv6By64(t *testing.T) {
	tests := map[string]string{
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::9": "2001:db8:1:2::/64",
		"203.0.113.7":          "203.0.113.7",
		"not-an-ip":            "not-an-ip",
	}
	for ip, want := range tests {
		if got := rateLimitKey(ip); got != want {
			t.Errorf("rateLimitKey(%q) = %q, want %q", ip, got, want)
		}
	}
}
