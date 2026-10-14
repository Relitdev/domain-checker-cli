package main

import (
	"os"
	"reflect"
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

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"sabintulung.desa.id": "desa.id",
		"batannyuh.desa.id":   "desa.id",
		"desa.id":             "desa.id",
		"sub.example.co.id":   "example.co.id",
		"example.co.id":       "example.co.id",
		"deep.sub.example.com": "example.com",
		"google.com":          "google.com",
	}
	for in, want := range cases {
		if got := registrableDomain(in); got != want {
			t.Fatalf("registrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadUptimeTargetsFromConfig(t *testing.T) {
	path := t.TempDir() + "/config.yml"
	content := "uptime:\n  - https://example.com\n  - https://example.org\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got := loadUptimeTargets("example.com", "", path)
	want := []string{"https://example.com", "https://example.org"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
