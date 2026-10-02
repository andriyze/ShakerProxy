package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Golden SHA-256 digests of the module matrix ('1' dark, '0' light, one row
// per line) produced by the reference python-qrcode 8.2 encoder with byte
// mode, error correction M, and each fixed mask.
var qrGoldens = []struct {
	data    string
	version int
	digests [8]string
}{
	{"http://10.77.0.1/", 2, [8]string{
		"fa1d7b995876e6642c1dda3fa7bd867eff39955ad990cb0eb6e1506fccff3a49",
		"4be2afaf0fc8ee94e1d6d887a762091c4f8a28bc29aacfec0aa0df6498228204",
		"6e2f6d221287add9199910093eca477016b93ec6066dfef4f37ade6895e646b6",
		"a2dffac777e7a6088aeaaf0774ae083a03dcbb3a0911eb56e9a9598ea39ebd62",
		"4af05d7ffedaceed19561707f0f51df7f46675f042dbd13a1fa072d0be918392",
		"99d720a9366b80ee43c306714803b4eeee02835659714bdd16821e2305486cf7",
		"ad6158e10df9b4fc65822d7cb41b2a6a508fd74dc3218f654a92140461354654",
		"1320c788ac30931ee1bc98899ec85431d9194328f1ddb925dce1e75d545b6058",
	}},
	{"https://shakerproxy.example/onboarding/" + strings.Repeat("a", 95), 8, [8]string{
		"32f02caa798aec0fe6f1751fb808eb37e3a06c900417cd1fc7bd53cd20c51d3c",
		"beb3b538de02ed675c86cc8d24cc520d479884ed09c612360767ea5a1e0351ab",
		"b47292d43aac08802c086469f8305d10fc3b8250ef6f28c99deff5b2a3a400a4",
		"c6ad29f4b92866f07969bac604bbbfcedde7be1cce014c12479a884b69c2d916",
		"cc7092cbf06e24402092b60894f191c751092ce480df71f62e54713217bf4449",
		"ab47b0d920a42b7fc465feec3308b85735b443ce3e76e15426256f7df58b3e0b",
		"86b8ae4bad59c800ea167f667d9f907eb7cef228596f6d12f461cb13680675a2",
		"f4e92b6ae577f69dc2aa1cf8e96fd8e76523e5840d98ae14c9335bfd18178c29",
	}},
	{"http://" + strings.Repeat("b", 193), 10, [8]string{
		"aa385d697f9d8b5d7cf9e4b9326a4d0936626dc4e1df70c4cf7f4d7ba0231e8f",
		"ccafb976d87fcec0a1b8da14255c10f784d21e949efd17f19b7994474b0a78e0",
		"08bb9af39f80312df124ced94b0ea4c7fbc25b16746bee16d6cd2041f071a783",
		"d7caabc9ed33cc59c129acb6baa2e91d4ef19ccbaf252c8b09188582a4747468",
		"c48baedd4b350a017f42c9d3dc9c741723158b3a26eb771e6fe8fb3228e39702",
		"b2abc51e738f67a06b93635976d25eb02ce0f3769144219824f38543754cadf5",
		"99c5fa68e25aee473c73cc3387493c246a21445ac712cc31384a6c10f6016946",
		"283114109353814d1aba1c8042b13b41c2d69881f6798e036db5c19e747f7833",
	}},
	{"http://" + strings.Repeat("d", 240), 11, [8]string{
		"79d516673ea5495a8df4f8c2bd00a1684eca4424db8ffa9de7f3cf1d881a204c",
		"8fa72d7f949cc8c5464320c3dbe8e1177452d7bd733833acfb2f40a0f8b9424f",
		"ddf1e2235591062eeab30e9d0b0ab397275e94bd7170d27cccb2467333d6bdc1",
		"e6da5d95aefd972c07581e77fd459f73030e135746503f9103a86f12db347227",
		"85fbfeda5b0cbda567f72ebd017d528ed2f2e036f6ab2df73bb6841b4f0861fd",
		"8f6abeb91d0acd7e7f9c0c6de13a2d598866a120b86dda276598b396f4f14856",
		"12b9b7437b9fb0d2c06cf1605296d5bb1e854da6f1ab37bc444706594dd48118",
		"ed096d34a368853c40316bc9108c821d5577fe50ad42f3e40f40583d696159e8",
	}},
	// A WireGuard VPN device configuration, as `shakerproxy vpn add` shows it.
	{"[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.89.0.2/32, fd12:3456:789a:1::2/128\nDNS = 10.89.0.1\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.168.10.177:51820\nPersistentKeepalive = 25\n", 12, [8]string{
		"c9c98f131da15d5cc7bc992628e76680e5fb10b68810a70b549cca4d0293058f",
		"1cd211d239eb5ce29dcf2b9127424ce2d43f89512a87608116ec955c8d4e47fe",
		"ab3e44ec442bf16d39d8d858c5a3d5e5a93510659e018aca444ce5c19b00f6c4",
		"3d62b957e96f212eee50693e7ff1d86f6a27bc4b4309a4eaa111e4ddc0eaa4c3",
		"1d59be470b25994e586381000ebf79a616c22086a13e224dccc9d5ed9cad783c",
		"74ddc17bd44028916024f078dbb1da9a01b1f83b68e4cc91b96610b615eebc18",
		"54259683437fe0a47e46d2707eaa9b4721ca3fddeb946315e707d4442ff62559",
		"7fa6c9b6943141ccc935dedf3bbe6c964f9df4588247614fb9f039b54583cb05",
	}},
	{"http://" + strings.Repeat("c", 600), 19, [8]string{
		"ee394e7fdd5e7712d2b75b9432a319ba809fd2fdda94f49c1430225b79423401",
		"c4f56d8895f171c93c7e9f47a1f5ee5ec5214371a23e7ab7ec5658ff04309dc6",
		"2e3483de2a60a18b7ec23e14f6aafc4296b37a4b40f4b497363cee38fc178de2",
		"ba65fc9b33f5eee985e8f1d52c71961188d61d6e071dbebf3be8fb0dfcba5687",
		"03ab00409fb9e90b173b00a9e19a144bc7ce7a74ae1d1d2116dd1e02eff847fb",
		"84275bb8bd22314e742cb7a5684673cf165e33a86cb5dc8eee5e41f326009c56",
		"ab1eae01ac82f831d9f6d78dcc8535231387512fc028902899f9ab6019860cad",
		"f58b1ee8366042616c1063b785e860e0facaa3e593c9403d703dfccc7c0cba68",
	}},
}

func TestQRMatchesReferenceEncoder(t *testing.T) {
	for _, golden := range qrGoldens {
		for mask := 0; mask < 8; mask++ {
			code, err := encodeQRWithMask([]byte(golden.data), mask)
			if err != nil {
				t.Fatalf("%d bytes mask %d: %v", len(golden.data), mask, err)
			}
			if code.version != golden.version {
				t.Fatalf("%d bytes chose version %d, want %d", len(golden.data), code.version, golden.version)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(code.text())))
			if digest != golden.digests[mask] {
				t.Fatalf("%d bytes version %d mask %d differs from the reference encoder:\n%s", len(golden.data), code.version, mask, code.text())
			}
		}
	}
}

func TestQRAutomaticMaskIsOneOfTheReferenceSymbols(t *testing.T) {
	golden := qrGoldens[0]
	code, err := encodeQR([]byte(golden.data))
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(code.text())))
	if digest != golden.digests[code.mask] {
		t.Fatalf("automatic mask %d produced a symbol that is not the reference symbol", code.mask)
	}
}

func TestQRRejectsOversizedPayload(t *testing.T) {
	if _, err := encodeQR(bytes.Repeat([]byte("x"), 666)); err != nil {
		t.Fatalf("encoder rejected a payload that fits version 20-M: %v", err)
	}
	if _, err := encodeQR(bytes.Repeat([]byte("x"), 667)); err == nil {
		t.Fatal("encoder accepted a payload beyond version 20-M")
	}
	if _, err := encodeQRWithMask([]byte("x"), 8); err == nil {
		t.Fatal("encoder accepted an invalid mask")
	}
}

func TestQRTerminalRendering(t *testing.T) {
	code, err := encodeQRWithMask([]byte("http://10.77.0.1/"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	code.render(&plain, false, "  ")
	lines := strings.Split(strings.TrimRight(plain.String(), "\n"), "\n")
	// 25 modules + 2x2 quiet zone = 29 rows, two rows per line.
	if len(lines) != 15 {
		t.Fatalf("unexpected line count %d:\n%s", len(lines), plain.String())
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "  ") || len([]rune(line)) != 2+29 {
			t.Fatalf("unexpected line width %d: %q", len([]rune(line)), line)
		}
	}
	// Line 1 holds module rows 0 and 1: the finder's dark top edge above
	// its dark-light-dark second row.
	if !strings.Contains(lines[1], "█▀▀▀▀▀█") {
		t.Fatalf("finder pattern edge missing: %q", lines[1])
	}
	var colored bytes.Buffer
	code.render(&colored, true, "")
	if !strings.HasPrefix(colored.String(), "\x1b[30;107m") || !strings.Contains(colored.String(), styleReset) {
		t.Fatal("coloured rendering does not force black-on-white")
	}
}
