// Minimal, dependency-free QR Code encoder (ISO/IEC 18004), byte mode only.
// Used to show the CA onboarding URL so a phone or TV can open it by camera.
// Keep this file free of runtime imports so node --test can load it directly.

export type QRErrorCorrection = "L" | "M" | "Q" | "H"

export type QRCode = {
  version: number
  size: number
  errorCorrection: QRErrorCorrection
  mask: number
  // modules[y][x] is true for a dark module.
  modules: boolean[][]
}

const FORMAT_BITS: Record<QRErrorCorrection, number> = { L: 1, M: 0, Q: 3, H: 2 }
const LEVEL_INDEX: Record<QRErrorCorrection, number> = { L: 0, M: 1, Q: 2, H: 3 }

// Error-correction codewords per block, indexed [level][version]; index 0 unused.
const ECC_CODEWORDS_PER_BLOCK: readonly (readonly number[])[] = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
]

// Number of error-correction blocks, indexed [level][version]; index 0 unused.
const ECC_BLOCKS: readonly (readonly number[])[] = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
]

const PENALTY_N1 = 3
const PENALTY_N2 = 3
const PENALTY_N3 = 40
const PENALTY_N4 = 10

function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64
  if (version >= 2) {
    const alignments = Math.floor(version / 7) + 2
    result -= (25 * alignments - 10) * alignments - 55
    if (version >= 7) result -= 36
  }
  return result
}

function dataCodewords(version: number, level: QRErrorCorrection): number {
  const index = LEVEL_INDEX[level]
  return Math.floor(rawDataModules(version) / 8) - ECC_CODEWORDS_PER_BLOCK[index][version] * ECC_BLOCKS[index][version]
}

// qrCapacityBytes returns how many bytes fit in byte mode at a version/level.
export function qrCapacityBytes(version: number, level: QRErrorCorrection): number {
  const countBits = version < 10 ? 8 : 16
  return Math.floor((dataCodewords(version, level) * 8 - 4 - countBits) / 8)
}

// ---- Reed–Solomon over GF(2^8) with the QR polynomial 0x11D ----

function gfMultiply(x: number, y: number): number {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z & 0xff
}

export function reedSolomonDivisor(degree: number): number[] {
  if (degree < 1 || degree > 255) throw new RangeError("Reed-Solomon degree out of range")
  const result: number[] = new Array(degree - 1).fill(0)
  result.push(1)
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMultiply(result[j], root)
      if (j + 1 < result.length) result[j] ^= result[j + 1]
    }
    root = gfMultiply(root, 0x02)
  }
  return result
}

export function reedSolomonRemainder(data: readonly number[], divisor: readonly number[]): number[] {
  const result: number[] = divisor.map(() => 0)
  for (const value of data) {
    const factor = value ^ (result.shift() as number)
    result.push(0)
    divisor.forEach((coefficient, index) => {
      result[index] ^= gfMultiply(coefficient, factor)
    })
  }
  return result
}

// ---- Data encoding ----

function encodeData(bytes: Uint8Array, version: number, level: QRErrorCorrection): number[] {
  const bits: number[] = []
  const push = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1)
  }
  push(0b0100, 4)
  push(bytes.length, version < 10 ? 8 : 16)
  for (const byte of bytes) push(byte, 8)
  const capacityBits = dataCodewords(version, level) * 8
  push(0, Math.min(4, capacityBits - bits.length))
  push(0, (8 - (bits.length % 8)) % 8)
  const codewords: number[] = []
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0
    for (let j = 0; j < 8; j++) value = (value << 1) | bits[i + j]
    codewords.push(value)
  }
  for (let pad = 0xec; codewords.length < capacityBits / 8; pad ^= 0xec ^ 0x11) codewords.push(pad)
  return codewords
}

function addErrorCorrection(data: number[], version: number, level: QRErrorCorrection): number[] {
  const index = LEVEL_INDEX[level]
  const blockCount = ECC_BLOCKS[index][version]
  const eccLength = ECC_CODEWORDS_PER_BLOCK[index][version]
  const rawCodewords = Math.floor(rawDataModules(version) / 8)
  const shortBlocks = blockCount - (rawCodewords % blockCount)
  const shortBlockLength = Math.floor(rawCodewords / blockCount)
  const divisor = reedSolomonDivisor(eccLength)
  const blocks: number[][] = []
  for (let i = 0, offset = 0; i < blockCount; i++) {
    const length = shortBlockLength - eccLength + (i < shortBlocks ? 0 : 1)
    const block = data.slice(offset, offset + length)
    offset += length
    const ecc = reedSolomonRemainder(block, divisor)
    if (i < shortBlocks) block.push(0)
    blocks.push(block.concat(ecc))
  }
  const result: number[] = []
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((block, j) => {
      if (i !== shortBlockLength - eccLength || j >= shortBlocks) result.push(block[i])
    })
  }
  return result
}

// ---- Matrix construction ----

type Matrix = { size: number; modules: boolean[][]; reserved: boolean[][] }

function newMatrix(size: number): Matrix {
  const grid = () => Array.from({ length: size }, () => new Array<boolean>(size).fill(false))
  return { size, modules: grid(), reserved: grid() }
}

function setFunction(matrix: Matrix, x: number, y: number, dark: boolean): void {
  matrix.modules[y][x] = dark
  matrix.reserved[y][x] = true
}

export function alignmentPositions(version: number): number[] {
  if (version === 1) return []
  const count = Math.floor(version / 7) + 2
  const size = version * 4 + 17
  const step = Math.floor((version * 8 + count * 3 + 5) / (count * 4 - 4)) * 2
  const result = [6]
  for (let position = size - 7; result.length < count; position -= step) result.splice(1, 0, position)
  return result
}

function drawFunctionPatterns(matrix: Matrix, version: number): void {
  const { size } = matrix
  for (let i = 0; i < size; i++) {
    setFunction(matrix, 6, i, i % 2 === 0)
    setFunction(matrix, i, 6, i % 2 === 0)
  }
  const finder = (cx: number, cy: number) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx
        const y = cy + dy
        if (x < 0 || x >= size || y < 0 || y >= size) continue
        const distance = Math.max(Math.abs(dx), Math.abs(dy))
        setFunction(matrix, x, y, distance !== 2 && distance !== 4)
      }
    }
  }
  finder(3, 3)
  finder(size - 4, 3)
  finder(3, size - 4)
  const positions = alignmentPositions(version)
  const last = positions.length - 1
  positions.forEach((py, i) => {
    positions.forEach((px, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) setFunction(matrix, px + dx, py + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
      }
    })
  })
  drawFormatBits(matrix, "M", 0)
  if (version >= 7) {
    let remainder = version
    for (let i = 0; i < 12; i++) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25)
    const bits = (version << 12) | remainder
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0
      const a = size - 11 + (i % 3)
      const b = Math.floor(i / 3)
      setFunction(matrix, a, b, dark)
      setFunction(matrix, b, a, dark)
    }
  }
}

export function formatBits(level: QRErrorCorrection, mask: number): number {
  const data = (FORMAT_BITS[level] << 3) | mask
  let remainder = data
  for (let i = 0; i < 10; i++) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537)
  return ((data << 10) | remainder) ^ 0x5412
}

function drawFormatBits(matrix: Matrix, level: QRErrorCorrection, mask: number): void {
  const { size } = matrix
  const bits = formatBits(level, mask)
  const bit = (i: number) => ((bits >>> i) & 1) !== 0
  for (let i = 0; i <= 5; i++) setFunction(matrix, 8, i, bit(i))
  setFunction(matrix, 8, 7, bit(6))
  setFunction(matrix, 8, 8, bit(7))
  setFunction(matrix, 7, 8, bit(8))
  for (let i = 9; i < 15; i++) setFunction(matrix, 14 - i, 8, bit(i))
  for (let i = 0; i < 8; i++) setFunction(matrix, size - 1 - i, 8, bit(i))
  for (let i = 8; i < 15; i++) setFunction(matrix, 8, size - 15 + i, bit(i))
  setFunction(matrix, 8, size - 8, true)
}

function drawCodewords(matrix: Matrix, codewords: number[]): void {
  const { size } = matrix
  let i = 0
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vertical = 0; vertical < size; vertical++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j
        const upward = ((right + 1) & 2) === 0
        const y = upward ? size - 1 - vertical : vertical
        if (!matrix.reserved[y][x] && i < codewords.length * 8) {
          matrix.modules[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0
          i++
        }
      }
    }
  }
}

function maskApplies(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0
    case 1: return y % 2 === 0
    case 2: return x % 3 === 0
    case 3: return (x + y) % 3 === 0
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0
    case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
    default: throw new RangeError("QR mask out of range")
  }
}

function applyMask(matrix: Matrix, mask: number): void {
  for (let y = 0; y < matrix.size; y++) {
    for (let x = 0; x < matrix.size; x++) {
      if (!matrix.reserved[y][x] && maskApplies(mask, x, y)) matrix.modules[y][x] = !matrix.modules[y][x]
    }
  }
}

function penaltyScore(matrix: Matrix): number {
  const { size, modules } = matrix
  let result = 0
  const addHistory = (length: number, history: number[]) => {
    if (history[0] === 0) length += size
    history.pop()
    history.unshift(length)
  }
  const countPatterns = (history: number[]) => {
    const n = history[1]
    const core = n > 0 && history[2] === n && history[3] === n * 3 && history[4] === n && history[5] === n
    return (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0) + (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0)
  }
  const terminate = (color: boolean, length: number, history: number[]) => {
    if (color) {
      addHistory(length, history)
      length = 0
    }
    addHistory(length + size, history)
    return countPatterns(history)
  }
  for (const vertical of [false, true]) {
    for (let a = 0; a < size; a++) {
      let color = false
      let run = 0
      const history = [0, 0, 0, 0, 0, 0, 0]
      for (let b = 0; b < size; b++) {
        const dark = vertical ? modules[b][a] : modules[a][b]
        if (dark === color) {
          run++
          if (run === 5) result += PENALTY_N1
          else if (run > 5) result++
        } else {
          addHistory(run, history)
          if (!color) result += countPatterns(history) * PENALTY_N3
          color = dark
          run = 1
        }
      }
      result += terminate(color, run, history) * PENALTY_N3
    }
  }
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const color = modules[y][x]
      if (color === modules[y][x + 1] && color === modules[y + 1][x] && color === modules[y + 1][x + 1]) result += PENALTY_N2
    }
  }
  let dark = 0
  for (const row of modules) for (const module of row) if (module) dark++
  const total = size * size
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1
  return result + k * PENALTY_N4
}

export type QROptions = { errorCorrection?: QRErrorCorrection; minVersion?: number; maxVersion?: number; mask?: number }

// encodeQR encodes text (UTF-8, byte mode) at the smallest version that fits.
// It throws a RangeError when the text is too long for maxVersion.
export function encodeQR(text: string, options: QROptions = {}): QRCode {
  const level = options.errorCorrection ?? "M"
  const minVersion = Math.max(1, options.minVersion ?? 1)
  const maxVersion = Math.min(40, options.maxVersion ?? 40)
  const bytes = new TextEncoder().encode(text)
  let version = minVersion
  while (version <= maxVersion && qrCapacityBytes(version, level) < bytes.length) version++
  if (version > maxVersion) throw new RangeError("Text is too long for a QR code")
  const codewords = addErrorCorrection(encodeData(bytes, version, level), version, level)
  const matrix = newMatrix(version * 4 + 17)
  drawFunctionPatterns(matrix, version)
  drawCodewords(matrix, codewords)
  let mask = options.mask ?? -1
  if (mask < 0 || mask > 7) {
    let best = Number.POSITIVE_INFINITY
    for (let candidate = 0; candidate < 8; candidate++) {
      applyMask(matrix, candidate)
      drawFormatBits(matrix, level, candidate)
      const score = penaltyScore(matrix)
      if (score < best) {
        best = score
        mask = candidate
      }
      applyMask(matrix, candidate)
    }
  }
  applyMask(matrix, mask)
  drawFormatBits(matrix, level, mask)
  return { version, size: matrix.size, errorCorrection: level, mask, modules: matrix.modules }
}

// qrSVGPath returns an SVG path (one unit per module) for the dark modules,
// offset by a quiet-zone border. Horizontal runs are merged to keep it small.
export function qrSVGPath(code: QRCode, border = 4): string {
  const parts: string[] = []
  code.modules.forEach((row, y) => {
    let x = 0
    while (x < code.size) {
      if (!row[x]) {
        x++
        continue
      }
      let end = x
      while (end < code.size && row[end]) end++
      parts.push(`M${x + border} ${y + border}h${end - x}v1h-${end - x}z`)
      x = end
    }
  })
  return parts.join("")
}
