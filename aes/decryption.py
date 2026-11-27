
"""AES-128 block decryption implementation."""

from .aes_tables import inv_sub_byte
from .gf_arithmetic import gf_multiply


def bytes_to_state(block: bytes) -> list:
    """Convert a 16-byte block into a 4x4 AES state matrix."""
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

    return [
        [block[4 * c + r] for c in range(4)]
        for r in range(4)
    ]


def state_to_bytes(state: list) -> bytes:
    """Convert a 4x4 AES state matrix into a 16-byte block."""
    return bytes(
        state[r][c]
        for c in range(4)
        for r in range(4)
    )


def inv_shift_rows(state: list) -> None:
    """Perform AES inverse ShiftRows transformation."""
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def inv_sub_bytes(state: list) -> None:
    """Perform AES inverse SubBytes transformation."""
    for r in range(4):
        for c in range(4):
            state[r][c] = inv_sub_byte(state[r][c])


def add_round_key(state: list, round_key: bytes) -> None:
    """Perform AES AddRoundKey transformation."""
    key_state = bytes_to_state(round_key)

    for r in range(4):
        for c in range(4):
            state[r][c] ^= key_state[r][c]


def inv_mix_columns(state: list) -> None:
    """Perform AES inverse MixColumns transformation."""

    inverse_matrix = [
        [0x0E, 0x0B, 0x0D, 0x09],
        [0x09, 0x0E, 0x0B, 0x0D],
        [0x0D, 0x09, 0x0E, 0x0B],
        [0x0B, 0x0D, 0x09, 0x0E]
    ]

    for c in range(4):
        column = [state[r][c] for r in range(4)]

        for r in range(4):
            result = 0

            for k in range(4):
                result ^= gf_multiply(
                    inverse_matrix[r][k],
                    column[k]
                )

            state[r][c] = result


def decrypt_block(ciphertext: bytes, round_keys: list) -> bytes:
    """Decrypt one 128-bit AES ciphertext block.

    Args:
        ciphertext: Exactly 16 bytes of ciphertext.
        round_keys: List containing 11 AES-128 round keys.

    Returns:
        The decrypted 16-byte plaintext block.
    """

    if len(ciphertext) != 16:
        raise ValueError("Ciphertext must be exactly 16 bytes")

    if len(round_keys) != 11:
        raise ValueError("AES-128 requires exactly 11 round keys")

    if any(len(key) != 16 for key in round_keys):
        raise ValueError("Each round key must be exactly 16 bytes")

    state = bytes_to_state(ciphertext)

    # Initial round: AddRoundKey with K10
    add_round_key(state, round_keys[10])

    # Rounds 9 down to 1
    for round_num in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_num])
        inv_mix_columns(state)

    # Final round: no inverse MixColumns
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)
