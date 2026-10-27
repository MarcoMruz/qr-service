package main

import (
	"errors"
	"unicode/utf8"

	"github.com/skip2/go-qrcode"
)

const (
	maxQRTextChars = 1000
	// maxQRTextBytes is the byte-mode capacity at Medium recovery; emoji-heavy text can hit it before the char limit.
	maxQRTextBytes = 2331
	qrImagePixels  = 512
)

var (
	errEmptyText   = errors.New("text is empty")
	errTextTooLong = errors.New("text is too long")
)

func generateQR(text string) ([]byte, error) {
	if text == "" {
		return nil, errEmptyText
	}
	if utf8.RuneCountInString(text) > maxQRTextChars || len(text) > maxQRTextBytes {
		return nil, errTextTooLong
	}
	return qrcode.Encode(text, qrcode.Medium, qrImagePixels)
}
