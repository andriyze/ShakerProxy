package coverage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// RFC 9001 Appendix A.1: the client Initial keys for DCID 0x8394c8f03e515708.
func TestClientInitialKeysMatchRFC9001(t *testing.T) {
	destinationID, _ := hex.DecodeString("8394c8f03e515708")
	keys, err := clientInitialKeys(destinationID)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"key": keys.key, "iv": keys.iv, "hp": keys.hp} {
		want := map[string]string{"key": "1f369613dd76d5467730efcbe3b1a22d", "iv": "fa044b2f42a3fd3b46fb255c", "hp": "9f50449e04a0e810283a1e9933adedd2"}[name]
		if hex.EncodeToString(got) != want {
			t.Fatalf("client %s = %x, want %s", name, got, want)
		}
	}
}

func readVarint(data []byte) (uint64, int) {
	length := 1 << (data[0] >> 6)
	value := uint64(data[0] & 0x3f)
	for index := 1; index < length; index++ {
		value = value<<8 | uint64(data[index])
	}
	return value, length
}

// The probe's packet must decrypt with the public Initial keys, as Zeek
// does, and carry a ClientHello naming the server.
func TestQUICInitialCarriesTheServerName(t *testing.T) {
	packet, err := BuildQUICInitial("quic-abc.coverage.shakerproxy.test", "h3")
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) < quicMinimumInitialSize {
		t.Fatalf("Initial packet is %d bytes, below the 1200-byte minimum", len(packet))
	}
	if packet[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(packet[1:5]) != 1 {
		t.Fatalf("not a QUIC v1 Initial long header: %x", packet[:5])
	}
	destinationID := packet[6 : 6+int(packet[5])]
	offset := 6 + len(destinationID)
	offset += 1 + int(packet[offset]) // source ID
	offset++                          // token length (0)
	length, size := readVarint(packet[offset:])
	offset += size
	keys, err := clientInitialKeys(destinationID)
	if err != nil {
		t.Fatal(err)
	}
	headerProtection, _ := aes.NewCipher(keys.hp)
	mask := make([]byte, 16)
	headerProtection.Encrypt(mask, packet[offset+4:offset+20])
	header := append([]byte(nil), packet[:offset+4]...)
	header[0] ^= mask[0] & 0x0f
	for index := 0; index < 4; index++ {
		header[offset+index] ^= mask[1+index]
	}
	if header[0]&0x03 != 3 || !bytes.Equal(header[offset:offset+4], []byte{0, 0, 0, 0}) {
		t.Fatalf("header protection did not round-trip: first byte %x packet number %x", header[0], header[offset:offset+4])
	}
	block, _ := aes.NewCipher(keys.key)
	aead, _ := cipher.NewGCM(block)
	plaintext, err := aead.Open(nil, keys.iv, packet[offset+4:offset+int(length)], header)
	if err != nil {
		t.Fatalf("Initial payload does not decrypt with the public keys: %v", err)
	}
	if plaintext[0] != 0x06 {
		t.Fatalf("first frame is %#x, want CRYPTO", plaintext[0])
	}
	if !bytes.Contains(plaintext, []byte("quic-abc.coverage.shakerproxy.test")) || !bytes.Contains(plaintext, []byte("h3")) {
		t.Fatal("ClientHello lacks the server name or ALPN")
	}
}
