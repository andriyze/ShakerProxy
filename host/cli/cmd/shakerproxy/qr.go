package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// A compact QR Code encoder (ISO/IEC 18004) for URLs and WireGuard
// configurations shown in the terminal: byte mode, error correction level M,
// versions 1-20 (up to 666 bytes). It follows the structure of Project
// Nayuki's reference encoder.

type qrCode struct {
	version int
	size    int
	mask    int
	modules [][]bool
}

type qrBlockSpec struct {
	eccPerBlock  int
	group1Blocks int
	group1Data   int
	group2Blocks int
	group2Data   int
}

// qrLevelM lists error-correction block structure for level M by version.
var qrLevelM = [...]qrBlockSpec{
	{},
	{10, 1, 16, 0, 0},
	{16, 1, 28, 0, 0},
	{26, 1, 44, 0, 0},
	{18, 2, 32, 0, 0},
	{24, 2, 43, 0, 0},
	{16, 4, 27, 0, 0},
	{18, 4, 31, 0, 0},
	{22, 2, 38, 2, 39},
	{22, 3, 36, 2, 37},
	{26, 4, 43, 1, 44},
	{30, 1, 50, 4, 51},
	{22, 6, 36, 2, 37},
	{22, 8, 37, 1, 38},
	{24, 4, 40, 5, 41},
	{24, 5, 41, 5, 42},
	{28, 7, 45, 3, 46},
	{28, 10, 46, 1, 47},
	{26, 9, 43, 4, 44},
	{26, 3, 44, 11, 45},
	{26, 3, 41, 13, 42},
}

var qrAlignmentCenters = [...][]int{nil, nil, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
	{6, 30, 54}, {6, 32, 58}, {6, 34, 62}, {6, 26, 46, 66}, {6, 26, 48, 70}, {6, 26, 50, 74}, {6, 30, 54, 78}, {6, 30, 56, 82}, {6, 30, 58, 86}, {6, 34, 62, 90}}

func (s qrBlockSpec) dataCodewords() int {
	return s.group1Blocks*s.group1Data + s.group2Blocks*s.group2Data
}

func encodeQR(data []byte) (*qrCode, error) { return encodeQRWithMask(data, -1) }

// encodeQRWithMask encodes data; mask -1 selects the lowest-penalty mask.
func encodeQRWithMask(data []byte, forcedMask int) (*qrCode, error) {
	if forcedMask < -1 || forcedMask > 7 {
		return nil, errors.New("QR mask must be between 0 and 7")
	}
	version := 0
	for candidate := 1; candidate < len(qrLevelM); candidate++ {
		if 4+qrCountBits(candidate)+len(data)*8 <= qrLevelM[candidate].dataCodewords()*8 {
			version = candidate
			break
		}
	}
	if version == 0 {
		return nil, fmt.Errorf("QR payload of %d bytes is too long", len(data))
	}
	spec := qrLevelM[version]
	capacityBits := spec.dataCodewords() * 8
	var bits []bool
	appendBits := func(value, length int) {
		for index := length - 1; index >= 0; index-- {
			bits = append(bits, (value>>index)&1 == 1)
		}
	}
	appendBits(0x4, 4)
	appendBits(len(data), qrCountBits(version))
	for _, value := range data {
		appendBits(int(value), 8)
	}
	appendBits(0, min(4, capacityBits-len(bits)))
	appendBits(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capacityBits; pad ^= 0xEC ^ 0x11 {
		appendBits(pad, 8)
	}
	codewords := make([]byte, len(bits)/8)
	for index, bit := range bits {
		if bit {
			codewords[index>>3] |= 1 << (7 - (index & 7))
		}
	}

	divisor := qrReedSolomonDivisor(spec.eccPerBlock)
	var dataBlocks, eccBlocks [][]byte
	offset := 0
	for index := 0; index < spec.group1Blocks+spec.group2Blocks; index++ {
		length := spec.group1Data
		if index >= spec.group1Blocks {
			length = spec.group2Data
		}
		block := codewords[offset : offset+length]
		offset += length
		dataBlocks = append(dataBlocks, block)
		eccBlocks = append(eccBlocks, qrReedSolomonRemainder(block, divisor))
	}
	var interleaved []byte
	for index := 0; index < max(spec.group1Data, spec.group2Data); index++ {
		for _, block := range dataBlocks {
			if index < len(block) {
				interleaved = append(interleaved, block[index])
			}
		}
	}
	for index := 0; index < spec.eccPerBlock; index++ {
		for _, block := range eccBlocks {
			interleaved = append(interleaved, block[index])
		}
	}

	code := &qrCode{version: version, size: version*4 + 17}
	code.modules = make([][]bool, code.size)
	function := make([][]bool, code.size)
	for row := range code.modules {
		code.modules[row] = make([]bool, code.size)
		function[row] = make([]bool, code.size)
	}
	set := func(x, y int, dark bool) {
		code.modules[y][x] = dark
		function[y][x] = true
	}
	code.drawFunctionPatterns(set)
	code.drawCodewords(interleaved, function)

	mask := forcedMask
	if mask < 0 {
		best := -1
		for candidate := 0; candidate < 8; candidate++ {
			code.applyMask(candidate, function)
			code.drawFormatBits(candidate, set)
			if penalty := code.penalty(); best < 0 || penalty < best {
				best, mask = penalty, candidate
			}
			code.applyMask(candidate, function)
		}
	}
	code.mask = mask
	code.applyMask(mask, function)
	code.drawFormatBits(mask, set)
	return code, nil
}

func qrCountBits(version int) int {
	if version >= 10 {
		return 16
	}
	return 8
}

func (q *qrCode) drawFunctionPatterns(set func(x, y int, dark bool)) {
	for index := 0; index < q.size; index++ {
		set(6, index, index%2 == 0)
		set(index, 6, index%2 == 0)
	}
	finder := func(centerX, centerY int) {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := centerX+dx, centerY+dy
				if x < 0 || y < 0 || x >= q.size || y >= q.size {
					continue
				}
				distance := max(abs(dx), abs(dy))
				set(x, y, distance != 2 && distance != 4)
			}
		}
	}
	finder(3, 3)
	finder(q.size-4, 3)
	finder(3, q.size-4)
	centers := qrAlignmentCenters[q.version]
	for i := range centers {
		for j := range centers {
			if (i == 0 && j == 0) || (i == 0 && j == len(centers)-1) || (i == len(centers)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					set(centers[i]+dx, centers[j]+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	q.drawFormatBits(0, set)
	if q.version >= 7 {
		remainder := q.version
		for index := 0; index < 12; index++ {
			remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1F25)
		}
		bits := q.version<<12 | remainder
		for index := 0; index < 18; index++ {
			dark := (bits>>index)&1 == 1
			a, b := q.size-11+index%3, index/3
			set(a, b, dark)
			set(b, a, dark)
		}
	}
}

// drawFormatBits writes the level-M format information for mask.
func (q *qrCode) drawFormatBits(mask int, set func(x, y int, dark bool)) {
	const levelMBits = 0
	data := levelMBits<<3 | mask
	remainder := data
	for index := 0; index < 10; index++ {
		remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537)
	}
	bits := (data<<10 | remainder) ^ 0x5412
	bit := func(index int) bool { return (bits>>index)&1 == 1 }
	for index := 0; index <= 5; index++ {
		set(8, index, bit(index))
	}
	set(8, 7, bit(6))
	set(8, 8, bit(7))
	set(7, 8, bit(8))
	for index := 9; index < 15; index++ {
		set(14-index, 8, bit(index))
	}
	for index := 0; index < 8; index++ {
		set(q.size-1-index, 8, bit(index))
	}
	for index := 8; index < 15; index++ {
		set(8, q.size-15+index, bit(index))
	}
	set(8, q.size-8, true)
}

func (q *qrCode) drawCodewords(data []byte, function [][]bool) {
	index := 0
	for right := q.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vertical := 0; vertical < q.size; vertical++ {
			for column := 0; column < 2; column++ {
				x := right - column
				upward := ((right + 1) & 2) == 0
				y := vertical
				if upward {
					y = q.size - 1 - vertical
				}
				if !function[y][x] && index < len(data)*8 {
					q.modules[y][x] = (data[index>>3]>>(7-(index&7)))&1 == 1
					index++
				}
			}
		}
	}
}

func (q *qrCode) applyMask(mask int, function [][]bool) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if function[y][x] {
				continue
			}
			var invert bool
			switch mask {
			case 0:
				invert = (x+y)%2 == 0
			case 1:
				invert = y%2 == 0
			case 2:
				invert = x%3 == 0
			case 3:
				invert = (x+y)%3 == 0
			case 4:
				invert = (x/3+y/2)%2 == 0
			case 5:
				invert = x*y%2+x*y%3 == 0
			case 6:
				invert = (x*y%2+x*y%3)%2 == 0
			case 7:
				invert = ((x+y)%2+x*y%3)%2 == 0
			}
			if invert {
				q.modules[y][x] = !q.modules[y][x]
			}
		}
	}
}

// penalty scores a masked symbol with the four ISO 18004 rules.
func (q *qrCode) penalty() int {
	score := 0
	at := func(x, y int, vertical bool) bool {
		if vertical {
			return q.modules[x][y]
		}
		return q.modules[y][x]
	}
	light := func(x, y int, vertical bool) bool {
		if x < 0 || x >= q.size {
			return true
		}
		return !at(x, y, vertical)
	}
	finderCore := []bool{true, false, true, true, true, false, true}
	for _, vertical := range []bool{false, true} {
		for y := 0; y < q.size; y++ {
			run := 1
			for x := 1; x <= q.size; x++ {
				if x < q.size && at(x, y, vertical) == at(x-1, y, vertical) {
					run++
					continue
				}
				if run >= 5 {
					score += 3 + run - 5
				}
				run = 1
			}
			for x := 0; x+7 <= q.size; x++ {
				matches := true
				for offset, dark := range finderCore {
					if at(x+offset, y, vertical) != dark {
						matches = false
						break
					}
				}
				if !matches {
					continue
				}
				before, after := true, true
				for offset := 1; offset <= 4; offset++ {
					before = before && light(x-offset, y, vertical)
					after = after && light(x+6+offset, y, vertical)
				}
				if before || after {
					score += 40
				}
			}
		}
	}
	dark := 0
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if q.modules[y][x] {
				dark++
			}
			if x+1 < q.size && y+1 < q.size {
				value := q.modules[y][x]
				if q.modules[y][x+1] == value && q.modules[y+1][x] == value && q.modules[y+1][x+1] == value {
					score += 3
				}
			}
		}
	}
	total := q.size * q.size
	k := (abs(dark*20-total*10)+total-1)/total - 1
	return score + k*10
}

func qrMultiply(x, y byte) byte {
	var z int
	for index := 7; index >= 0; index-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		z ^= int((y>>index)&1) * int(x)
	}
	return byte(z)
}

func qrReedSolomonDivisor(degree int) []byte {
	result := make([]byte, degree)
	result[degree-1] = 1
	root := byte(1)
	for index := 0; index < degree; index++ {
		for j := range result {
			result[j] = qrMultiply(result[j], root)
			if j+1 < len(result) {
				result[j] ^= result[j+1]
			}
		}
		root = qrMultiply(root, 0x02)
	}
	return result
}

func qrReedSolomonRemainder(data, divisor []byte) []byte {
	result := make([]byte, len(divisor))
	for _, value := range data {
		factor := value ^ result[0]
		copy(result, result[1:])
		result[len(result)-1] = 0
		for index, coefficient := range divisor {
			result[index] ^= qrMultiply(coefficient, factor)
		}
	}
	return result
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// render draws the symbol with half-block characters (two module rows per
// text line) and a two-module quiet zone. With colour, it forces black on
// white so it scans on dark terminal themes too.
func (q *qrCode) render(w io.Writer, color bool, indent string) {
	const quiet = 2
	dark := func(x, y int) bool {
		if x < 0 || y < 0 || x >= q.size || y >= q.size {
			return false
		}
		return q.modules[y][x]
	}
	for y := -quiet; y < q.size+quiet; y += 2 {
		var line strings.Builder
		line.WriteString(indent)
		if color {
			line.WriteString("\x1b[30;107m")
		}
		for x := -quiet; x < q.size+quiet; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				line.WriteString("█")
			case top:
				line.WriteString("▀")
			case bottom:
				line.WriteString("▄")
			default:
				line.WriteString(" ")
			}
		}
		if color {
			line.WriteString(styleReset)
		}
		fmt.Fprintln(w, line.String())
	}
}

// text returns the matrix as rows of '1' (dark) and '0' (light).
func (q *qrCode) text() string {
	var builder strings.Builder
	for _, row := range q.modules {
		for _, module := range row {
			if module {
				builder.WriteByte('1')
			} else {
				builder.WriteByte('0')
			}
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}
