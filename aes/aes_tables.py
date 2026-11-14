# AES Tables

def sub_byte(value: int) -> int:
    """Apply AES S-Box substitution to a single byte.

    Args:
        value (int): Byte value (0-255).
    Returns:
        int: Substituted byte.
    """
    if not (0 <= value <= 0xFF):
        raise ValueError("Byte value must be in 0..255")
    raise NotImplementedError

def inv_sub_byte(value: int) -> int:
    """Inverse S-Box substitution.

    Args:
        value (int): Byte value (0-255).
    Returns:
        int: Inverse substituted byte.
    """
    if not (0 <= value <= 0xFF):
        raise ValueError("Byte value must be in 0..255")
    raise NotImplementedError
