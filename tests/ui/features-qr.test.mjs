import assert from "node:assert/strict"
import test from "node:test"
import { alignmentPositions, encodeQR, formatBits, qrCapacityBytes, qrSVGPath, reedSolomonDivisor, reedSolomonRemainder } from "../../apps/web-ui/src/features/qr.ts"

const rows = (code) => code.modules.map((row) => row.map((dark) => (dark ? "1" : "0")).join(""))

// Golden matrices produced by independent encoders (segno, python-qrcode) with ISO padding.
const GOLDEN = [
  {
    text: "ShakerProxy CA", level: "M", mask: 5, version: 1,
    rows: ["111111100001001111111", "100000101100001000001", "101110101101101011101", "101110101111101011101", "101110100110101011101", "100000100100101000001", "111111101010101111111", "000000001001100000000", "100000101000111001110", "110101010010101100000", "000111110111101000110", "001001010101010001111", "101100111111110111011", "000000001100111100110", "111111100011111001110", "100000100100111001100", "101110100100111100011", "101110100000001110000", "101110100111111010011", "100000100111110101100", "111111101010011000010"],
  },
  {
    text: "http://10.77.0.1/", level: "M", mask: 2, version: 2,
    rows: ["1111111000010101001111111", "1000001001111111101000001", "1011101011010100101011101", "1011101011001010001011101", "1011101010010000001011101", "1000001011001001101000001", "1111111010101010101111111", "0000000010100011000000000", "1011111000100001101111100", "1010110110010110000000010", "1011011111010111010001011", "1010110001101100100000001", "1001011111111010001110111", "1011000101100000010001010", "1000101101111001011101011", "1000110101110011010001001", "1011011001010001111110100", "0000000010001110100011100", "1111111001000110101011111", "1000001010001101100011011", "1011101011101011111111101", "1011101010100001101110111", "1011101011111000110000101", "1000001001010011111111001", "1111111010110001010111111"],
  },
]

test("Reed-Solomon matches the ISO 18004 HELLO WORLD 1-M example", () => {
  const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
  assert.deepEqual(reedSolomonRemainder(data, reedSolomonDivisor(10)), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23])
})

test("format information bits match the standard table", () => {
  assert.equal(formatBits("L", 0).toString(2).padStart(15, "0"), "111011111000100")
  assert.equal(formatBits("M", 0).toString(2).padStart(15, "0"), "101010000010010")
  assert.equal(formatBits("Q", 0).toString(2).padStart(15, "0"), "011010101011111")
  assert.equal(formatBits("H", 0).toString(2).padStart(15, "0"), "001011010001001")
  assert.equal(formatBits("L", 4).toString(2).padStart(15, "0"), "110011000101111")
})

test("alignment pattern centres and byte capacities match the standard", () => {
  assert.deepEqual(alignmentPositions(1), [])
  assert.deepEqual(alignmentPositions(2), [6, 18])
  assert.deepEqual(alignmentPositions(7), [6, 22, 38])
  assert.deepEqual(alignmentPositions(32), [6, 34, 60, 86, 112, 138])
  assert.deepEqual(alignmentPositions(40), [6, 30, 58, 86, 114, 142, 170])
  const capacities = { 1: [17, 14, 11, 7], 2: [32, 26, 20, 14], 10: [271, 213, 151, 119], 40: [2953, 2331, 1663, 1273] }
  for (const [version, expected] of Object.entries(capacities)) {
    assert.deepEqual(["L", "M", "Q", "H"].map((level) => qrCapacityBytes(Number(version), level)), expected, `version ${version}`)
  }
})

test("encoded symbols match an independent encoder module for module", () => {
  for (const golden of GOLDEN) {
    const code = encodeQR(golden.text, { errorCorrection: golden.level, mask: golden.mask })
    assert.equal(code.version, golden.version)
    assert.deepEqual(rows(code), golden.rows, golden.text)
  }
})

test("automatic mask selection yields a valid symbol with readable format bits", () => {
  const code = encodeQR("http://10.77.0.1/")
  assert.equal(code.version, 2)
  assert.equal(code.size, 25)
  assert.ok(code.mask >= 0 && code.mask <= 7)
  // Format bits: first copy around the top-left finder.
  const m = code.modules
  const read = [0, 1, 2, 3, 4, 5].map((i) => m[i][8]).concat([m[7][8], m[8][8], m[8][7]], [5, 4, 3, 2, 1, 0].map((i) => m[8][i]))
  const value = read.reduce((acc, bit, i) => acc | ((bit ? 1 : 0) << i), 0)
  assert.equal(value, formatBits("M", code.mask))
  // Dark module and finder corners.
  assert.equal(m[code.size - 8][8], true)
  for (const [x, y] of [[0, 0], [code.size - 7, 0], [0, code.size - 7]]) {
    assert.equal(m[y][x], true)
    assert.equal(m[y + 1][x + 1], false)
    assert.equal(m[y + 3][x + 3], true)
  }
})

test("UTF-8 text, version growth and overflow are handled", () => {
  // 15 UTF-8 bytes: one more than version 1-M holds.
  assert.equal(encodeQR("Ünïcødé ✓").version, 2)
  assert.equal(encodeQR("Ünïcødé").version, 1)
  assert.ok(encodeQR("x".repeat(300)).version > 10)
  assert.throws(() => encodeQR("x".repeat(3000)), RangeError)
  assert.throws(() => encodeQR("x".repeat(100), { maxVersion: 3 }), RangeError)
})

test("SVG path merges horizontal runs inside the quiet zone", () => {
  const code = encodeQR("ShakerProxy CA", { mask: 5 })
  const path = qrSVGPath(code, 4)
  assert.match(path, /^M4 4h7v1h-7z/)
  assert.doesNotMatch(path, /NaN|undefined/)
})
