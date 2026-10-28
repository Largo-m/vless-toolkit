"""Pure-Python QR Code generation for share links.

This module implements byte-mode QR codes for versions 1-10 with the low error
correction level. That is enough for typical proxy share links while keeping
the implementation small and dependency-free. Output is ASCII so it renders in
terminals, logs and chat without Unicode block support.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import LinkValidationError

_MAX_VERSION = 10
_ECC_CODEWORDS_PER_BLOCK = {
    1: 7,
    2: 10,
    3: 15,
    4: 20,
    5: 26,
    6: 18,
    7: 20,
    8: 24,
    9: 30,
    10: 18,
}
_NUM_ERROR_CORRECTION_BLOCKS = {1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 2, 7: 2, 8: 2, 9: 2, 10: 4}
_ALIGNMENT_POSITIONS = {
    1: (),
    2: (6, 18),
    3: (6, 22),
    4: (6, 26),
    5: (6, 30),
    6: (6, 34),
    7: (6, 22, 38),
    8: (6, 24, 42),
    9: (6, 26, 46),
    10: (6, 28, 50),
}
_FORMAT_BITS_L = 0b01


def _get_bit(value: int, index: int) -> bool:
    """Return one bit, with index 0 as the least-significant bit."""
    return ((value >> index) & 1) != 0


def _num_raw_data_modules(version: int) -> int:
    """Return the number of data modules for a QR version."""
    result = (16 * version + 128) * version + 64
    if version >= 2:
        num_align = version // 7 + 2
        result -= (25 * num_align - 10) * num_align - 55
        if version >= 7:
            result -= 36
    return result


def _num_data_codewords(version: int) -> int:
    """Return the number of data codewords for version 1-10 at ECC level L."""
    total = _num_raw_data_modules(version) // 8
    return total - _ECC_CODEWORDS_PER_BLOCK[version] * _NUM_ERROR_CORRECTION_BLOCKS[version]


def _gf_multiply(left: int, right: int) -> int:
    """Multiply two bytes in GF(2^8) with the QR polynomial 0x11D."""
    result = 0
    for index in range(7, -1, -1):
        result = (result << 1) ^ ((result >> 7) * 0x11D)
        result ^= ((right >> index) & 1) * left
    return result


def _reed_solomon_divisor(degree: int) -> list[int]:
    """Compute the Reed-Solomon generator polynomial without its leading 1."""
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for index in range(degree):
            result[index] = _gf_multiply(result[index], root)
            if index + 1 < degree:
                result[index] ^= result[index + 1]
        root = _gf_multiply(root, 0x02)
    return result


def _reed_solomon_remainder(data: bytes, divisor: list[int]) -> bytes:
    """Compute Reed-Solomon error correction codewords."""
    result = [0] * len(divisor)
    for value in data:
        factor = value ^ result.pop(0)
        result.append(0)
        for index, coefficient in enumerate(divisor):
            result[index] ^= _gf_multiply(coefficient, factor)
    return bytes(result)


def _data_bits(data: bytes, version: int) -> list[int]:
    """Encode bytes in QR byte mode with terminator and padding."""
    capacity = _num_data_codewords(version) * 8
    count_bits = 8 if version <= 9 else 16
    if 4 + count_bits + len(data) * 8 > capacity:
        raise LinkValidationError("share link is too long for a version 10 QR code")
    bits = [0, 1, 0, 0]
    bits.extend(_get_bit(len(data), index) for index in range(count_bits - 1, -1, -1))
    for value in data:
        bits.extend(_get_bit(value, index) for index in range(7, -1, -1))
    bits.extend([0] * min(4, capacity - len(bits)))
    bits.extend([0] * ((-len(bits)) % 8))

    result = bytearray()
    for index in range(0, len(bits), 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | bit
        result.append(value)
    pad_byte = 0xEC
    while len(result) < capacity // 8:
        result.append(pad_byte)
        pad_byte = 0x11 if pad_byte == 0xEC else 0xEC
    return list(result)


def _add_error_correction(data: list[int], version: int) -> list[int]:
    """Split data into blocks, add ECC, and interleave codewords."""
    num_blocks = _NUM_ERROR_CORRECTION_BLOCKS[version]
    ecc_length = _ECC_CODEWORDS_PER_BLOCK[version]
    short_length, long_count = divmod(len(data), num_blocks)
    num_short_blocks = num_blocks - long_count

    blocks: list[list[int]] = []
    offset = 0
    for index in range(num_blocks):
        length = short_length + (0 if index < num_short_blocks else 1)
        block = data[offset : offset + length]
        offset += length
        blocks.append(block)

    result: list[int] = []
    for index in range(max(len(block) for block in blocks)):
        for block in blocks:
            if index < len(block):
                result.append(block[index])
    divisors = [_reed_solomon_divisor(ecc_length) for _ in blocks]
    ecc_blocks = [
        _reed_solomon_remainder(bytes(block), divisor)
        for block, divisor in zip(blocks, divisors)
    ]
    for index in range(ecc_length):
        for block in ecc_blocks:
            result.append(block[index])
    return result


def _choose_version(data_length: int) -> int:
    """Choose the smallest supported version that fits the data."""
    for version in range(1, _MAX_VERSION + 1):
        count_bits = 8 if version <= 9 else 16
        if 4 + count_bits + data_length * 8 <= _num_data_codewords(version) * 8:
            return version
    raise LinkValidationError("share link is too long for a version 10 QR code")


def _mask_bit(mask: int, x: int, y: int) -> bool:
    """Return the mask condition for a module coordinate."""
    if mask == 0:
        return (x + y) % 2 == 0
    if mask == 1:
        return y % 2 == 0
    if mask == 2:
        return x % 3 == 0
    if mask == 3:
        return (x + y) % 3 == 0
    if mask == 4:
        return (x // 3 + y // 2) % 2 == 0
    if mask == 5:
        return (x * y) % 2 + (x * y) % 3 == 0
    if mask == 6:
        return ((x * y) % 2 + (x * y) % 3) % 2 == 0
    return ((x + y) % 2 + (x * y) % 3) % 2 == 0


@dataclass(frozen=True)
class QRCode:
    """A generated QR Code matrix.

    Attributes:
        version: QR version (1-10).
        mask: Applied data mask (0-7).
        modules: Row-major boolean matrix, where ``True`` means dark.
    """

    version: int
    mask: int
    modules: tuple[tuple[bool, ...], ...]

    @property
    def size(self) -> int:
        """Number of modules per side."""
        return len(self.modules)


class _MatrixBuilder:
    """Build one QR matrix for a fixed version and mask."""

    def __init__(self, version: int) -> None:
        self.version = version
        self.size = version * 4 + 17
        self.modules = [[False] * self.size for _ in range(self.size)]
        self.is_function = [[False] * self.size for _ in range(self.size)]

    def set_function(self, x: int, y: int, dark: bool) -> None:
        """Set a module that belongs to a function pattern."""
        if 0 <= x < self.size and 0 <= y < self.size:
            self.modules[y][x] = dark
            self.is_function[y][x] = True

    def _draw_finder(self, center_x: int, center_y: int) -> None:
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                distance = max(abs(dx), abs(dy))
                self.set_function(center_x + dx, center_y + dy, distance not in (2, 4))

    def _draw_alignment(self, center_x: int, center_y: int) -> None:
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                distance = max(abs(dx), abs(dy))
                self.set_function(center_x + dx, center_y + dy, distance != 1)

    def _draw_function_patterns(self) -> None:
        for index in range(self.size):
            self.set_function(6, index, index % 2 == 0)
            self.set_function(index, 6, index % 2 == 0)

        self._draw_finder(3, 3)
        self._draw_finder(self.size - 4, 3)
        self._draw_finder(3, self.size - 4)

        align = _ALIGNMENT_POSITIONS[self.version]
        for index, x in enumerate(align):
            for other_index, y in enumerate(align):
                if (index, other_index) in ((0, 0), (0, len(align) - 1), (len(align) - 1, 0)):
                    continue
                self._draw_alignment(x, y)

        self._draw_format_bits(0)
        self._draw_version()

    def _draw_version(self) -> None:
        if self.version < 7:
            return
        remainder = self.version
        for _ in range(12):
            remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1F25)
        bits = (self.version << 12) | remainder
        for index in range(18):
            dark = _get_bit(bits, index)
            first = self.size - 11 + index % 3
            second = index // 3
            self.set_function(first, second, dark)
            self.set_function(second, first, dark)

    def _draw_format_bits(self, mask: int) -> None:
        data = (_FORMAT_BITS_L << 3) | mask
        remainder = data
        for _ in range(10):
            remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537)
        bits = (data << 10 | remainder) ^ 0x5412

        for index in range(6):
            self.set_function(8, index, _get_bit(bits, index))
        self.set_function(8, 7, _get_bit(bits, 6))
        self.set_function(8, 8, _get_bit(bits, 7))
        self.set_function(7, 8, _get_bit(bits, 8))
        for index in range(9, 15):
            self.set_function(14 - index, 8, _get_bit(bits, index))
        for index in range(8):
            self.set_function(self.size - 1 - index, 8, _get_bit(bits, index))
        for index in range(8, 15):
            self.set_function(8, self.size - 15 + index, _get_bit(bits, index))
        self.set_function(8, self.size - 8, True)

    def draw_codewords(self, codewords: list[int]) -> None:
        bit_index = 0
        right = self.size - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vertical in range(self.size):
                for offset in range(2):
                    x = right - offset
                    upward = ((right + 1) & 2) == 0
                    y = self.size - 1 - vertical if upward else vertical
                    if not self.is_function[y][x] and bit_index < len(codewords) * 8:
                        self.modules[y][x] = _get_bit(
                            codewords[bit_index >> 3], 7 - (bit_index & 7)
                        )
                        bit_index += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        for y in range(self.size):
            for x in range(self.size):
                if not self.is_function[y][x] and _mask_bit(mask, x, y):
                    self.modules[y][x] = not self.modules[y][x]

    def penalty(self) -> int:
        """Score the matrix according to the QR mask penalty rules."""
        score = 0
        for line in self._rows_and_columns():
            run = 1
            for index in range(1, len(line)):
                if line[index] == line[index - 1]:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run = 1
            if run >= 5:
                score += 3 + run - 5
            text = "".join("1" if bit else "0" for bit in line)
            for pattern in ("10111010000", "00001011101"):
                start = 0
                while True:
                    found = text.find(pattern, start)
                    if found < 0:
                        break
                    score += 40
                    start = found + 1

        for y in range(self.size - 1):
            for x in range(self.size - 1):
                color = self.modules[y][x]
                if (
                    self.modules[y][x + 1] == color
                    and self.modules[y + 1][x] == color
                    and self.modules[y + 1][x + 1] == color
                ):
                    score += 3

        dark = sum(sum(row) for row in self.modules)
        total = self.size * self.size
        score += abs(dark * 20 - total * 10) // total * 10
        return score

    def _rows_and_columns(self) -> list[list[bool]]:
        rows = [row[:] for row in self.modules]
        columns = [[self.modules[y][x] for y in range(self.size)] for x in range(self.size)]
        return rows + columns


def encode_qr(text: str) -> QRCode:
    """Encode UTF-8 text as a low-error-correction QR Code.

    Args:
        text: Text to encode, typically a single share link.

    Returns:
        A :class:`QRCode` with the chosen version and mask.

    Raises:
        LinkValidationError: If the text is empty or too long for version 10.
    """
    if not isinstance(text, str):
        raise LinkValidationError("QR input must be a string")
    if not text:
        raise LinkValidationError("QR input must not be empty")
    data = text.encode("utf-8")
    version = _choose_version(len(data))
    codewords = _add_error_correction(_data_bits(data, version), version)

    best: _MatrixBuilder | None = None
    best_mask = 0
    best_penalty: int | None = None
    for mask in range(8):
        builder = _MatrixBuilder(version)
        builder._draw_function_patterns()
        builder.draw_codewords(codewords)
        builder.apply_mask(mask)
        builder._draw_format_bits(mask)
        score = builder.penalty()
        if best_penalty is None or score < best_penalty:
            best = builder
            best_mask = mask
            best_penalty = score
    if best is None:  # pragma: no cover - all eight masks always run
        raise LinkValidationError("could not generate a QR code")
    modules = tuple(tuple(row) for row in best.modules)
    return QRCode(version=version, mask=best_mask, modules=modules)


def qr_to_ascii(qr: QRCode, *, border: int = 4) -> str:
    """Render a QR Code as ASCII art using ``##`` for dark modules.

    Args:
        qr: Matrix returned by :func:`encode_qr`.
        border: Quiet-zone width in modules, normally four.

    Raises:
        LinkValidationError: If the matrix or border is invalid.
    """
    if not isinstance(qr, QRCode):
        raise LinkValidationError("qr_to_ascii expects a QRCode instance")
    if isinstance(border, bool) or not isinstance(border, int) or not 0 <= border <= 16:
        raise LinkValidationError("QR border must be an integer between 0 and 16")

    width = qr.size + border * 2
    lines: list[str] = []
    for y in range(width):
        cells: list[str] = []
        for x in range(width):
            qr_x = x - border
            qr_y = y - border
            dark = (
                0 <= qr_x < qr.size
                and 0 <= qr_y < qr.size
                and qr.modules[qr_y][qr_x]
            )
            cells.append("##" if dark else "  ")
        lines.append("".join(cells).rstrip())
    return "\n".join(lines) + "\n"


def link_to_ascii_qr(text: str, *, border: int = 4) -> str:
    """Encode text and render it directly as an ASCII QR Code."""
    return qr_to_ascii(encode_qr(text), border=border)

