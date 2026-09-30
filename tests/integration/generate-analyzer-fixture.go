package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const fixtureSessionID = "capture-0123456789abcdef0123456789abcdef"

func main() {
	if len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) || filepath.Clean(os.Args[1]) == "/" {
		fmt.Fprintln(os.Stderr, "usage: generate-analyzer-fixture <absolute-capture-root>")
		os.Exit(2)
	}
	if err := generate(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(root string) error {
	artifacts := filepath.Join(root, fixtureSessionID, "artifacts")
	runtime := filepath.Join(root, fixtureSessionID, "runtime")
	for _, directory := range []string{artifacts, runtime} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	path := filepath.Join(artifacts, "capture_00001.pcapng")
	packets := fixturePackets()
	contents := encodePCAPNG(packets)
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	artifactDigest := sha256.Sum256(contents)
	sessionDigest := sha256.Sum256([]byte("ShakerProxy analyzer integration fixture v1"))
	manifest := capture.Manifest{
		Schema: capture.SchemaVersion, SessionID: fixtureSessionID, CreatedAt: time.Date(2026, 9, 1, 12, 0, 1, 0, time.UTC), SessionSHA256: hex.EncodeToString(sessionDigest[:]),
		Files: []capture.CaptureFile{{Name: filepath.Base(path), SizeBytes: info.Size(), SHA256: hex.EncodeToString(artifactDigest[:]), Modified: info.ModTime().UTC()}}, TotalSizeBytes: info.Size(), PacketsCaptured: uint64(len(packets)), PacketsReceived: uint64(len(packets)),
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(filepath.Join(runtime, "manifest.json"), encoded, 0o644)
}

func fixturePackets() [][]byte {
	client := [4]byte{10, 77, 0, 111}
	server := [4]byte{10, 77, 0, 1}
	request := []byte("GET /authorized-fixture HTTP/1.1\r\nHost: shakerproxy.test\r\nAuthorization: Basic dXNlcjpwYXNz\r\nConnection: close\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
	return [][]byte{
		tcpPacket(client, server, 40123, 80, 1000, 0, 0x02, nil),
		tcpPacket(server, client, 80, 40123, 9000, 1001, 0x12, nil),
		tcpPacket(client, server, 40123, 80, 1001, 9001, 0x10, nil),
		tcpPacket(client, server, 40123, 80, 1001, 9001, 0x18, request),
		tcpPacket(server, client, 80, 40123, 9001, uint32(1001+len(request)), 0x10, nil),
		tcpPacket(server, client, 80, 40123, 9001, uint32(1001+len(request)), 0x18, response),
		tcpPacket(client, server, 40123, 80, uint32(1001+len(request)), uint32(9001+len(response)), 0x10, nil),
	}
}

func tcpPacket(source, destination [4]byte, sourcePort, destinationPort uint16, sequence, acknowledgement uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 14+20+20+len(payload))
	copy(packet[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(packet[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	binary.BigEndian.PutUint16(ip[4:6], uint16(sequence&0xffff))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], source[:])
	copy(ip[16:20], destination[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	tcp := packet[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], acknowledgement)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(packet[54:], payload)
	pseudo := make([]byte, 12+len(tcp)+len(payload))
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], destination[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)+len(payload)))
	copy(pseudo[12:32], tcp)
	copy(pseudo[32:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return packet
}

func checksum(contents []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(contents); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(contents[index : index+2]))
	}
	if len(contents)%2 == 1 {
		sum += uint32(contents[len(contents)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func encodePCAPNG(packets [][]byte) []byte {
	result := make([]byte, 0, 4096)
	result = appendBlock(result, 0x0a0d0d0a, func(body []byte) []byte {
		body = binary.LittleEndian.AppendUint32(body, 0x1a2b3c4d)
		body = binary.LittleEndian.AppendUint16(body, 1)
		body = binary.LittleEndian.AppendUint16(body, 0)
		return binary.LittleEndian.AppendUint64(body, ^uint64(0))
	})
	result = appendBlock(result, 1, func(body []byte) []byte {
		body = binary.LittleEndian.AppendUint16(body, 1)
		body = binary.LittleEndian.AppendUint16(body, 0)
		return binary.LittleEndian.AppendUint32(body, 262144)
	})
	baseMicros := uint64(1788278400) * 1_000_000
	for index, packet := range packets {
		timestamp := baseMicros + uint64(index*1000)
		captured := len(packet)
		result = appendBlock(result, 6, func(body []byte) []byte {
			body = binary.LittleEndian.AppendUint32(body, 0)
			body = binary.LittleEndian.AppendUint32(body, uint32(timestamp>>32))
			body = binary.LittleEndian.AppendUint32(body, uint32(timestamp))
			body = binary.LittleEndian.AppendUint32(body, uint32(captured))
			body = binary.LittleEndian.AppendUint32(body, uint32(captured))
			body = append(body, packet...)
			for len(body)%4 != 0 {
				body = append(body, 0)
			}
			return body
		})
	}
	return result
}

func appendBlock(destination []byte, blockType uint32, body func([]byte) []byte) []byte {
	start := len(destination)
	destination = binary.LittleEndian.AppendUint32(destination, blockType)
	destination = binary.LittleEndian.AppendUint32(destination, 0)
	destination = body(destination)
	length := uint32(len(destination) - start + 4)
	binary.LittleEndian.PutUint32(destination[start+4:start+8], length)
	destination = binary.LittleEndian.AppendUint32(destination, length)
	return destination
}
