from .aes_tables import INV_S_BOX
from .gf_arithmetic import gf_multiply


def bytes_to_state(block):
    """Convert 16-byte block into AES 4x4 State Matrix."""

    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

    return [
        [block[4 * c + r] for c in range(4)]
        for r in range(4)
    ]


def state_to_bytes(state):
    """Convert AES State Matrix into 16 bytes."""

    return bytes(
        state[r][c]
        for c in range(4)
        for r in range(4)
    )


def inv_shift_rows(state):
    """Circularly shift rows to the right."""

    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def inv_sub_bytes(state):
    """Replace each byte using the Inverse S-Box."""

    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]


def add_round_key(state, round_key):
    """XOR the State Matrix with a round key."""

    key_state = bytes_to_state(round_key)

    for r in range(4):
        for c in range(4):
            state[r][c] ^= key_state[r][c]


def inv_mix_columns(state):
    """Perform AES Inverse MixColumns."""

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


def decrypt_block(ciphertext, round_keys):
    """
    AES-128 decryption.

    Input:
        ciphertext: 16-byte ciphertext
        round_keys: 11 round keys

    Output:
        16-byte recovered plaintext
    """

    if len(ciphertext) != 16:
        raise ValueError("Ciphertext must be exactly 16 bytes")

    if len(round_keys) != 11:
        raise ValueError("AES-128 requires exactly 11 round keys")

    if any(len(key) != 16 for key in round_keys):
        raise ValueError("Each round key must be exactly 16 bytes")

    # Convert ciphertext into State Matrix
    state = bytes_to_state(ciphertext)

    # Initial AddRoundKey (K10)
    add_round_key(state, round_keys[10])

    # Main decryption rounds (9 to 1)
    for round_num in range(9, 0, -1):

        inv_shift_rows(state)

        inv_sub_bytes(state)

        add_round_key(state, round_keys[round_num])

        inv_mix_columns(state)

    # Final decryption round (K0)
    inv_shift_rows(state)

    inv_sub_bytes(state)

    add_round_key(state, round_keys[0])

    # Return recovered plaintext
    return state_to_bytes(state)
