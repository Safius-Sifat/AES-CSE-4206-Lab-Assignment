def gf_multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) using the AES irreducible polynomial 0x11b.

    Args:
        a (int): First byte (0-255).
        b (int): Second byte (0-255).
    Returns:
        int: Result of multiplication modulo the AES field.
    """
    if not (0 <= a <= 0xFF and 0 <= b <= 0xFF):
        raise ValueError("Inputs must be bytes (0-255)")
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1b  # AES polynomial (x^8 + x^4 + x^3 + x + 1)
        b >>= 1
    return p
