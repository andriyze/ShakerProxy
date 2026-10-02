package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// Key is a WireGuard Curve25519 key. It encodes as standard base64, the
// form WireGuard configurations and apps use.
type Key [32]byte

// NewPrivateKey returns a fresh, clamped Curve25519 private key.
func NewPrivateKey() (Key, error) {
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		return Key{}, errors.New("generate WireGuard key")
	}
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return key, nil
}

// PublicKey derives the public key of a private key.
func (k Key) PublicKey() Key {
	public, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// Only a low-order point can fail, and a clamped scalar times the
		// base point never is one.
		panic("vpn: derive WireGuard public key: " + err.Error())
	}
	var result Key
	copy(result[:], public)
	return result
}

// IsZero reports an unset key.
func (k Key) IsZero() bool { return k == Key{} }

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// ParseKey decodes a base64 WireGuard key.
func ParseKey(text string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) != len(Key{}) {
		return Key{}, errors.New("WireGuard keys are 32 bytes of base64")
	}
	var key Key
	copy(key[:], raw)
	return key, nil
}

func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Key) UnmarshalText(text []byte) error {
	parsed, err := ParseKey(string(text))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}
