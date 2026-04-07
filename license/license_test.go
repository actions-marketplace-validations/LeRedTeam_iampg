// Copyright (C) 2026 LeRedTeam
// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// testSetup generates a keypair and overrides the package-level public key
// for testing. Returns the private key base64 and a cleanup function.
func testSetup(t *testing.T) string {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Override the package-level public key for validation
	original := publicKeyBase64
	publicKeyBase64 = base64.RawURLEncoding.EncodeToString(pub)
	t.Cleanup(func() {
		publicKeyBase64 = original
		cachedLicense = nil
	})

	return base64.RawURLEncoding.EncodeToString(priv)
}

func generateTestKey(t *testing.T, privKey string, tier Tier, validDays int) string {
	t.Helper()
	key, err := GenerateLicenseKey(privKey, "test@example.com", tier, validDays)
	if err != nil {
		t.Fatalf("GenerateLicenseKey failed: %v", err)
	}
	return key
}

func TestValidateValidKey(t *testing.T) {
	privKey := testSetup(t)
	key := generateTestKey(t, privKey, TierPro, 365)

	license, err := Validate(key)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if license.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", license.Email, "test@example.com")
	}
	if license.Tier != TierPro {
		t.Errorf("Tier = %q, want %q", license.Tier, TierPro)
	}
	if license.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt is in the past")
	}
}

func TestValidateAllTiers(t *testing.T) {
	privKey := testSetup(t)

	tiers := []Tier{TierFree, TierPro, TierTeam, TierCommercial}
	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			key := generateTestKey(t, privKey, tier, 365)
			license, err := Validate(key)
			if err != nil {
				t.Fatalf("Validate failed for tier %s: %v", tier, err)
			}
			if license.Tier != tier {
				t.Errorf("Tier = %q, want %q", license.Tier, tier)
			}
		})
	}
}

func TestValidateInvalidBase64(t *testing.T) {
	_, err := Validate("not-valid-base64!!!")
	if err != ErrInvalidLicense {
		t.Errorf("err = %v, want ErrInvalidLicense", err)
	}
}

func TestValidateInvalidJSON(t *testing.T) {
	garbage := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, err := Validate(garbage)
	if err != ErrInvalidLicense {
		t.Errorf("err = %v, want ErrInvalidLicense", err)
	}
}

func TestValidateInvalidSignature(t *testing.T) {
	privKey := testSetup(t)
	key := generateTestKey(t, privKey, TierPro, 365)

	// Decode, tamper with payload, re-encode
	keyBytes, _ := base64.RawURLEncoding.DecodeString(key)
	var signed SignedLicense
	json.Unmarshal(keyBytes, &signed)

	// Create a different payload but keep the old signature
	payload := Payload{
		Email:     "hacker@evil.com",
		Tier:      TierPro,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().AddDate(10, 0, 0).Unix(),
	}
	payloadBytes, _ := json.Marshal(payload)
	signed.Payload = base64.RawURLEncoding.EncodeToString(payloadBytes)

	tamperedBytes, _ := json.Marshal(signed)
	tampered := base64.RawURLEncoding.EncodeToString(tamperedBytes)

	_, err := Validate(tampered)
	if err != ErrInvalidLicense {
		t.Errorf("err = %v, want ErrInvalidLicense for tampered key", err)
	}
}

func TestValidateExpiredPastGracePeriod(t *testing.T) {
	privKey := testSetup(t)
	// Generate a key that expired 30 days ago (well past 7-day grace)
	key := generateTestKey(t, privKey, TierPro, -30)

	_, err := Validate(key)
	if err != ErrExpiredLicense {
		t.Errorf("err = %v, want ErrExpiredLicense", err)
	}
}

func TestValidateExpiredInGracePeriod(t *testing.T) {
	privKey := testSetup(t)
	// Generate a key that expired 3 days ago (within 7-day grace)
	key := generateTestKey(t, privKey, TierPro, -3)

	license, err := Validate(key)
	if err != nil {
		t.Fatalf("Validate should succeed in grace period, got: %v", err)
	}
	if license.Tier != TierPro {
		t.Errorf("Tier = %q, want %q", license.Tier, TierPro)
	}
}

func TestHasFeatureFreeTier(t *testing.T) {
	l := &License{Tier: TierFree}

	// Free features should work
	freeFeatures := []string{"run", "parse", "json"}
	for _, f := range freeFeatures {
		if !l.HasFeature(f) {
			t.Errorf("Free tier should have feature %q", f)
		}
	}

	// Pro features should NOT work
	proFeatures := []string{"refine", "yaml", "terraform", "sarif", "enforce", "diff", "aggregate"}
	for _, f := range proFeatures {
		if l.HasFeature(f) {
			t.Errorf("Free tier should NOT have feature %q", f)
		}
	}
}

func TestHasFeatureProTier(t *testing.T) {
	l := &License{Tier: TierPro}

	allFeatures := []string{"run", "parse", "json", "refine", "yaml", "terraform", "sarif", "enforce", "diff", "aggregate", "wildcards", "scoping"}
	for _, f := range allFeatures {
		if !l.HasFeature(f) {
			t.Errorf("Pro tier should have feature %q", f)
		}
	}
}

func TestHasFeatureCommercialTier(t *testing.T) {
	l := &License{Tier: TierCommercial}

	allFeatures := []string{"run", "parse", "json", "refine", "yaml", "terraform", "sarif", "enforce", "diff", "aggregate", "wildcards", "scoping"}
	for _, f := range allFeatures {
		if !l.HasFeature(f) {
			t.Errorf("Commercial tier should have feature %q", f)
		}
	}
}

func TestHasFeatureTeamTier(t *testing.T) {
	l := &License{Tier: TierTeam}

	allFeatures := []string{"run", "parse", "json", "refine", "yaml", "terraform", "sarif", "enforce", "diff", "aggregate"}
	for _, f := range allFeatures {
		if !l.HasFeature(f) {
			t.Errorf("Team tier should have feature %q", f)
		}
	}
}

func TestHasFeatureUnknown(t *testing.T) {
	l := &License{Tier: TierPro}
	if l.HasFeature("nonexistent") {
		t.Error("Should return false for unknown feature")
	}
}

func TestIsPaid(t *testing.T) {
	tests := []struct {
		tier Tier
		want bool
	}{
		{TierFree, false},
		{TierPro, true},
		{TierTeam, true},
		{TierCommercial, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.tier), func(t *testing.T) {
			l := &License{Tier: tt.tier}
			if got := l.IsPaid(); got != tt.want {
				t.Errorf("IsPaid() = %v, want %v for tier %s", got, tt.want, tt.tier)
			}
		})
	}
}

func TestGenerateKeyPairRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Override public key with the generated one
	original := publicKeyBase64
	publicKeyBase64 = kp.PublicKey
	defer func() {
		publicKeyBase64 = original
		cachedLicense = nil
	}()

	key, err := GenerateLicenseKey(kp.PrivateKey, "roundtrip@test.com", TierPro, 30)
	if err != nil {
		t.Fatalf("GenerateLicenseKey failed: %v", err)
	}

	license, err := Validate(key)
	if err != nil {
		t.Fatalf("Validate failed on round-trip key: %v", err)
	}
	if license.Email != "roundtrip@test.com" {
		t.Errorf("Email = %q, want %q", license.Email, "roundtrip@test.com")
	}
	if license.Tier != TierPro {
		t.Errorf("Tier = %q, want %q", license.Tier, TierPro)
	}
}

func TestGenerateLicenseKeyInvalidPrivateKey(t *testing.T) {
	_, err := GenerateLicenseKey("not-a-key", "test@test.com", TierPro, 30)
	if err == nil {
		t.Error("Expected error for invalid private key")
	}
}

func TestGenerateLicenseKeyWrongKeySize(t *testing.T) {
	shortKey := base64.RawURLEncoding.EncodeToString([]byte("tooshort"))
	_, err := GenerateLicenseKey(shortKey, "test@test.com", TierPro, 30)
	if err == nil {
		t.Error("Expected error for wrong key size")
	}
}
