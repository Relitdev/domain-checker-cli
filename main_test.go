package main

import (
	"testing"
	"time"
)

func TestParseWhoisExpiry(t *testing.T) {
	input := `Domain Name: example.com
Registry Expiry Date: 2026-12-31T00:00:00Z
Updated Date: 2025-01-15T00:00:00Z`

	expiry, ok := parseWhoisExpiry(input)
	if !ok {
		t.Fatal("expected expiration to be parsed")
	}

	want := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	if !expiry.Equal(want) {
		t.Fatalf("expected %v, got %v", want, expiry)
	}
}

func TestParseWhoisExpiryAlternativeFormats(t *testing.T) {
	input := `Domain Status: ok
paid-till: 2027-02-14T00:00:00Z
Domain: test.id`

	expiry, ok := parseWhoisExpiry(input)
	if !ok {
		t.Fatal("expected alternative expiry format to be parsed")
	}

	want := time.Date(2027, 2, 14, 0, 0, 0, 0, time.UTC)
	if !expiry.Equal(want) {
		t.Fatalf("expected %v, got %v", want, expiry)
	}
}
