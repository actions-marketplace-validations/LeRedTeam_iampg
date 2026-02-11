package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Tier represents a license tier.
type Tier string

const (
	TierFree Tier = "free"
	TierPro  Tier = "pro"
	TierTeam Tier = "team"
)

// License represents a validated license.
type License struct {
	Email     string    `json:"email"`
	Tier      Tier      `json:"tier"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
}

// Payload is the unsigned license data.
type Payload struct {
	Email     string `json:"email"`
	Tier      Tier   `json:"tier"`
	ExpiresAt int64  `json:"expires_at"`
	IssuedAt  int64  `json:"issued_at"`
}

// SignedLicense is the format stored in the license key.
type SignedLicense struct {
	Payload   string `json:"p"`
	Signature string `json:"s"`
}

var (
	ErrNoLicense      = errors.New("no license key found")
	ErrInvalidLicense = errors.New("invalid license key")
	ErrExpiredLicense = errors.New("license has expired")
	ErrInvalidTier    = errors.New("feature not available in your tier")
)

// Public key for license validation (embedded at build time for releases)
// This is the PUBLIC key - safe to embed in the binary
// Generate a new keypair with: iampg license generate-keypair
// Override with -ldflags "-X github.com/LeRedTeam/iampg/license.publicKeyBase64=..."
var publicKeyBase64 = "ReQfxJ3z-YxhjVvFT1jT5qZTiCJjHSDV4bmVt9p8YoM"

var cachedLicense *License

// Current returns the current license, reading from environment if needed.
func Current() (*License, error) {
	if cachedLicense != nil {
		return cachedLicense, nil
	}

	key := os.Getenv("IAMPG_LICENSE_KEY")
	if key == "" {
		return &License{Tier: TierFree}, nil
	}

	license, err := Validate(key)
	if err != nil {
		return nil, err
	}

	cachedLicense = license
	return license, nil
}

// Validate validates a license key and returns the license if valid.
func Validate(key string) (*License, error) {
	// Decode the license key
	keyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, ErrInvalidLicense
	}

	var signed SignedLicense
	if err := json.Unmarshal(keyBytes, &signed); err != nil {
		return nil, ErrInvalidLicense
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		return nil, ErrInvalidLicense
	}

	// Decode public key
	publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, ErrInvalidLicense
	}

	// Verify signature
	if !ed25519.Verify(publicKey, []byte(signed.Payload), signature) {
		return nil, ErrInvalidLicense
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(signed.Payload)
	if err != nil {
		return nil, ErrInvalidLicense
	}

	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalidLicense
	}

	// Check expiration
	expiresAt := time.Unix(payload.ExpiresAt, 0)
	if time.Now().After(expiresAt) {
		// Grace period: 7 days after expiration
		gracePeriod := expiresAt.Add(7 * 24 * time.Hour)
		if time.Now().After(gracePeriod) {
			return nil, ErrExpiredLicense
		}
		// In grace period - warn but allow
		fmt.Fprintf(os.Stderr, "Warning: License expired on %s. Grace period ends %s.\n",
			expiresAt.Format("2006-01-02"), gracePeriod.Format("2006-01-02"))
	}

	return &License{
		Email:     payload.Email,
		Tier:      payload.Tier,
		ExpiresAt: expiresAt,
		IssuedAt:  time.Unix(payload.IssuedAt, 0),
	}, nil
}

// HasFeature checks if the current license has access to a feature.
func HasFeature(feature string) bool {
	license, err := Current()
	if err != nil {
		return false
	}
	return license.HasFeature(feature)
}

// HasFeature checks if the license has access to a feature.
func (l *License) HasFeature(feature string) bool {
	// Free tier features
	freeFeatures := map[string]bool{
		"run":   true,
		"parse": true,
		"json":  true,
	}

	// Pro tier features (includes free)
	proFeatures := map[string]bool{
		"refine":     true,
		"yaml":       true,
		"terraform":  true,
		"sarif":      true,
		"enforce":    true,
		"diff":       true,
		"aggregate":  true,
		"wildcards":  true,
		"scoping":    true,
	}

	// Check free features first
	if freeFeatures[feature] {
		return true
	}

	// Check paid features
	if l.Tier == TierPro || l.Tier == TierTeam {
		return proFeatures[feature]
	}

	return false
}

// RequireFeature checks if the license has access and returns an error if not.
func RequireFeature(feature string) error {
	license, err := Current()
	if err != nil {
		return err
	}

	if !license.HasFeature(feature) {
		return fmt.Errorf("%w: '%s' requires a Pro license. Set IAMPG_LICENSE_KEY or upgrade at https://github.com/LeRedTeam/iampg", ErrInvalidTier, feature)
	}

	return nil
}

// IsPaid returns true if the license is a paid tier.
func (l *License) IsPaid() bool {
	return l.Tier == TierPro || l.Tier == TierTeam
}
