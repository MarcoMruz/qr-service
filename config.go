package main

import (
	"errors"
	"strconv"
	"unicode/utf8"
)

const (
	minSecretLength   = 32
	minPasswordLength = 12
)

type config struct {
	addr          string
	password      string
	sessionSecret string
	trustProxy    bool
}

func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{
		addr:          getenv("ADDR"),
		password:      getenv("APP_PASSWORD"),
		sessionSecret: getenv("SESSION_SECRET"),
	}
	if cfg.addr == "" {
		cfg.addr = ":8080"
	}
	if !utf8.ValidString(cfg.password) || utf8.RuneCountInString(cfg.password) < minPasswordLength {
		return cfg, errors.New("APP_PASSWORD must be at least 12 characters")
	}
	if len(cfg.sessionSecret) < minSecretLength {
		return cfg, errors.New("SESSION_SECRET must be at least 32 characters")
	}
	if raw := getenv("TRUST_PROXY"); raw != "" {
		trustProxy, err := strconv.ParseBool(raw)
		if err != nil {
			return cfg, errors.New("TRUST_PROXY must be true or false")
		}
		cfg.trustProxy = trustProxy
	}
	return cfg, nil
}
