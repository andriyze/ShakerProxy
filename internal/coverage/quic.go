package coverage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"time"
)

// QUIC v1 (RFC 9000/9001) Initial packets are encrypted with keys anyone can
// derive from the destination connection ID, which is how Zeek reads a
// QUIC client's server name. The coverage probe sends a real client Initial
// so the QUIC check exercises the same analyzer a phone's HTTP/3 traffic does.

var quicV1InitialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

const quicMinimumInitialSize = 1200

type quicInitialKeys struct {
	key, iv, hp []byte
}

func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func clientInitialKeys(destinationID []byte) (quicInitialKeys, error) {
	initial, err := hkdf.Extract(sha256.New, destinationID, quicV1InitialSalt)
	if err != nil {
		return quicInitialKeys{}, err
	}
	client, err := hkdfExpandLabel(initial, "client in", 32)
	if err != nil {
		return quicInitialKeys{}, err
	}
	var keys quicInitialKeys
	if keys.key, err = hkdfExpandLabel(client, "quic key", 16); err != nil {
		return quicInitialKeys{}, err
	}
	if keys.iv, err = hkdfExpandLabel(client, "quic iv", 12); err != nil {
		return quicInitialKeys{}, err
	}
	if keys.hp, err = hkdfExpandLabel(client, "quic hp", 16); err != nil {
		return quicInitialKeys{}, err
	}
	return keys, nil
}

func appendVarint(out []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(out, byte(value))
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(out, uint16(value)|0x4000)
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(out, uint32(value)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(out, value|0xc000000000000000)
	}
}

// quicClientHello produces a TLS 1.3 ClientHello for QUIC with the given
// server name and ALPN, using crypto/tls's QUIC handshake.
func quicClientHello(serverName, alpn string, sourceID []byte) ([]byte, error) {
	config := &tls.QUICConfig{TLSConfig: &tls.Config{ServerName: serverName, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}}
	connection := tls.QUICClient(config)
	defer connection.Close()
	// initial_source_connection_id (0x0f) and a small initial_max_data
	// (0x04); RFC 9000 section 18.2.
	parameters := appendVarint(nil, 0x0f)
	parameters = appendVarint(parameters, uint64(len(sourceID)))
	parameters = append(parameters, sourceID...)
	parameters = appendVarint(parameters, 0x04)
	parameters = appendVarint(parameters, 4)
	parameters = appendVarint(parameters, 1<<20)
	connection.SetTransportParameters(parameters)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := connection.Start(ctx); err != nil {
		return nil, err
	}
	var hello []byte
	for {
		event := connection.NextEvent()
		switch event.Kind {
		case tls.QUICNoEvent:
			if len(hello) == 0 {
				return nil, errors.New("TLS produced no QUIC ClientHello")
			}
			return hello, nil
		case tls.QUICWriteData:
			if event.Level == tls.QUICEncryptionLevelInitial {
				hello = append(hello, event.Data...)
			}
		case tls.QUICTransportParametersRequired:
			connection.SetTransportParameters(parameters)
		}
	}
}

// BuildQUICInitial returns one UDP payload: a QUIC v1 client Initial packet
// carrying a ClientHello for serverName and alpn, padded to 1200 bytes.
func BuildQUICInitial(serverName, alpn string) ([]byte, error) {
	destinationID := make([]byte, 8)
	sourceID := make([]byte, 8)
	if _, err := rand.Read(destinationID); err != nil {
		return nil, err
	}
	if _, err := rand.Read(sourceID); err != nil {
		return nil, err
	}
	hello, err := quicClientHello(serverName, alpn, sourceID)
	if err != nil {
		return nil, err
	}
	keys, err := clientInitialKeys(destinationID)
	if err != nil {
		return nil, err
	}
	const packetNumberLength = 4
	payload := []byte{0x06} // CRYPTO frame
	payload = appendVarint(payload, 0)
	payload = appendVarint(payload, uint64(len(hello)))
	payload = append(payload, hello...)
	headerLength := 1 + 4 + 1 + len(destinationID) + 1 + len(sourceID) + 1 + 2 + packetNumberLength
	if padding := quicMinimumInitialSize - headerLength - len(payload) - 16; padding > 0 {
		payload = append(payload, make([]byte, padding)...) // PADDING frames
	}
	header := []byte{0xc0 | (packetNumberLength - 1)} // long header, Initial
	header = binary.BigEndian.AppendUint32(header, 1)
	header = append(header, byte(len(destinationID)))
	header = append(header, destinationID...)
	header = append(header, byte(len(sourceID)))
	header = append(header, sourceID...)
	header = append(header, 0) // no token
	header = binary.BigEndian.AppendUint16(header, uint16(packetNumberLength+len(payload)+16)|0x4000)
	packetNumberOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, 0) // packet number 0
	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Packet number 0, so the nonce is the IV itself.
	packet := aead.Seal(append([]byte(nil), header...), keys.iv, payload, header)
	headerProtection, err := aes.NewCipher(keys.hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, aes.BlockSize)
	headerProtection.Encrypt(mask, packet[packetNumberOffset+4:packetNumberOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	for index := 0; index < packetNumberLength; index++ {
		packet[packetNumberOffset+index] ^= mask[1+index]
	}
	return packet, nil
}
