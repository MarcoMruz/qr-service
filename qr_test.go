package main

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateQRAcceptsMultibyteTextUpToCharLimit(t *testing.T) {
	// 1000 two-byte chars are within both limits even though they exceed 1000 bytes.
	if _, err := generateQR(strings.Repeat("š", maxQRTextChars)); err != nil {
		t.Fatalf("want accented text at the char limit to encode, got %v", err)
	}
}

func TestGenerateQRRejectsInvalidInput(t *testing.T) {
	tests := map[string]struct {
		text string
		want error
	}{
		"empty":          {"", errEmptyText},
		"too many chars": {strings.Repeat("a", maxQRTextChars+1), errTextTooLong},
		"too many bytes": {strings.Repeat("😀", 600), errTextTooLong},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := generateQR(tc.text); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}
